"""Organization scan requests, persistent daily/weekly schedules and cross-process job claims."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, time, timedelta
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, field_validator, model_validator

from .diagnostics import PublicFailure
from .models import Model, now
from .storage import Store


class ScanSchedule(Model):
    frequency: Literal["daily", "weekly"]
    time_of_day: str = Field(pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    timezone: str = "UTC"
    weekday: int | None = Field(default=None, ge=0, le=6)

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError):
            raise ValueError(
                "Choose an IANA timezone, such as UTC or America/Los_Angeles"
            ) from None
        return value

    @model_validator(mode="after")
    def weekly_needs_day(self) -> ScanSchedule:
        if self.frequency == "weekly" and self.weekday is None:
            raise ValueError("Choose a weekday for a weekly schedule")
        return self

    def next_after(self, instant: datetime) -> datetime:
        """Return the next UTC occurrence; DST gaps move forward and folds run only once."""
        if instant.tzinfo is None:
            raise ValueError("Schedule calculation requires a timezone-aware timestamp")
        zone = ZoneInfo(self.timezone)
        start = instant.astimezone(zone).date()
        clock = time.fromisoformat(self.time_of_day)
        for days in range(15):
            date = start + timedelta(days=days)
            if self.frequency == "weekly" and date.weekday() != self.weekday:
                continue
            wall = datetime.combine(date, clock)
            # Find the first existing local minute at/after the requested clock time.
            while wall.date() == date:
                candidates = []
                for fold in (0, 1):
                    candidate = wall.replace(tzinfo=zone, fold=fold).astimezone(UTC)
                    if candidate.astimezone(zone).replace(tzinfo=None) == wall:
                        candidates.append(candidate)
                if candidates:
                    first = min(candidates)
                    if first > instant:
                        return first
                    break  # Never run again during the second occurrence of a DST fold.
                wall += timedelta(minutes=1)
        raise ValueError("No schedule occurrence found")


class ScanControl:
    """Persist scan controls behind the same organization fencing as all application state."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def schedule(self, generation: int) -> dict[str, Any] | None:
        """Read the active organization's schedule and next UTC execution time."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            row = db.execute(
                "SELECT * FROM scan_schedule WHERE generation=?", (generation,)
            ).fetchone()
        return dict(row) if row else None

    def save(
        self, generation: int, schedule: ScanSchedule, instant: datetime | None = None
    ) -> None:
        """Replace the single active daily/weekly schedule atomically."""
        instant = instant or now()
        with self.store.db() as db:
            self.store.fence(db, generation)
            db.execute(
                "INSERT OR REPLACE INTO scan_schedule VALUES(1,?,?,?)",
                (generation, schedule.model_dump_json(), schedule.next_after(instant).isoformat()),
            )

    def disable(self, generation: int) -> None:
        """Disable recurrence without deleting queued requests or historical runs."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            db.execute("DELETE FROM scan_schedule WHERE generation=?", (generation,))

    def enqueue(
        self, generation: int, actor: str, source: str = "manual", *, followup: bool = False
    ) -> str:
        """Queue a full scan; repeated clicks coalesce with already queued/running work."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            state = db.execute("SELECT parent,blocked FROM state WHERE id=1").fetchone()
            if not state[0] or state[1]:
                raise PublicFailure("Verify the parent scanner credentials before starting a scan.")
            current = db.execute(
                "SELECT id FROM scan_jobs WHERE generation=? AND "
                "(status='queued' OR (status='running' AND ?=0)) "
                "ORDER BY requested_at LIMIT 1",
                (generation, int(followup)),
            ).fetchone()
            if current:
                return str(current[0])
            ident = secrets.token_hex(16)
            db.execute(
                "INSERT INTO scan_jobs(id,generation,source,actor,status,requested_at) "
                "VALUES(?,?,?,?,'queued',?)",
                (ident, generation, source, actor, now().isoformat()),
            )
            return ident

    def enqueue_due(self, generation: int, instant: datetime | None = None) -> str | None:
        """Atomically queue at most one missed occurrence and advance to the next future time."""
        instant = instant or now()
        with self.store.db() as db:
            self.store.fence(db, generation)
            row = db.execute(
                "SELECT * FROM scan_schedule WHERE generation=?", (generation,)
            ).fetchone()
            if not row or datetime.fromisoformat(row["next_run"]) > instant:
                return None
            # A blocked scanner retains its due time, so it retries after credential repair.
            if db.execute("SELECT blocked FROM state WHERE id=1").fetchone()[0]:
                return None
            current = db.execute(
                "SELECT id FROM scan_jobs WHERE generation=? AND status IN ('queued','running')",
                (generation,),
            ).fetchone()
            ident = str(current[0]) if current else secrets.token_hex(16)
            if not current:
                db.execute(
                    "INSERT INTO scan_jobs(id,generation,source,actor,status,requested_at) "
                    "VALUES(?,?,'scheduled','scheduler','queued',?)",
                    (ident, generation, instant.isoformat()),
                )
            schedule = ScanSchedule.model_validate_json(row["data"])
            db.execute(
                "UPDATE scan_schedule SET next_run=? WHERE id=1",
                (schedule.next_after(instant).isoformat(),),
            )
            return ident

    def heartbeat(self, instant: datetime | None = None) -> None:
        """Publish scanner liveness independently of organization data."""
        with self.store.db() as db:
            db.execute(
                "INSERT OR REPLACE INTO scan_worker VALUES(1,?)", ((instant or now()).isoformat(),)
            )

    def online(self) -> bool:
        """Treat a worker heartbeat older than 30 seconds as offline."""
        with self.store.db() as db:
            row = db.execute("SELECT heartbeat FROM scan_worker WHERE id=1").fetchone()
        return bool(row and now() - datetime.fromisoformat(row[0]) < timedelta(seconds=30))

    def jobs(self, generation: int) -> list[dict[str, Any]]:
        """Read the most recent 50 scan requests for this organization."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            rows = db.execute(
                "SELECT * FROM scan_jobs WHERE generation=? ORDER BY requested_at DESC LIMIT 50",
                (generation,),
            ).fetchall()
        return [dict(row) for row in rows]

    def claim(
        self, generation: int, owner: str, instant: datetime | None = None
    ) -> dict[str, Any] | None:
        """Claim a queued job atomically; recover expired jobs without overlapping live reads."""
        instant = instant or now()
        with self.store.db() as db:
            self.store.fence(db, generation)
            dead = [
                str(row[0])
                for row in db.execute(
                    "SELECT owner FROM scan_jobs WHERE status='running' AND lease_expires<?",
                    (instant.isoformat(),),
                )
                if row[0]
            ]
            # A worker that stopped renewing its job also stopped renewing its tenancy leases;
            # release them now instead of waiting out their full duration. Other processes'
            # leases (for example a CLI scan) are untouched. A hung worker is fenced, not raced.
            for owner_id in dead:
                db.execute(
                    "DELETE FROM leases WHERE substr(owner,1,?)=?",
                    (len(owner_id) + 1, owner_id + ":"),
                )
            db.execute(
                "UPDATE scan_jobs SET status='interrupted',finished_at=?,error=? "
                "WHERE status='running' AND lease_expires<?",
                (
                    instant.isoformat(),
                    "Scanner stopped before the run completed; retry the scan.",
                    instant.isoformat(),
                ),
            )
            if db.execute("SELECT blocked FROM state WHERE id=1").fetchone()[0]:
                return None
            if db.execute("SELECT 1 FROM scan_jobs WHERE status='running'").fetchone():
                return None
            # Existing CLI reads or an interrupted worker must drain before another full run.
            if db.execute(
                "SELECT 1 FROM leases WHERE expires>?", (instant.isoformat(),)
            ).fetchone():
                return None
            row = db.execute(
                "SELECT * FROM scan_jobs WHERE generation=? AND status='queued' "
                "ORDER BY requested_at LIMIT 1",
                (generation,),
            ).fetchone()
            if not row:
                return None
            db.execute(
                "UPDATE scan_jobs SET status='running',started_at=?,owner=?,lease_expires=? "
                "WHERE id=?",
                (
                    instant.isoformat(),
                    owner,
                    (instant + timedelta(seconds=120)).isoformat(),
                    row["id"],
                ),
            )
            return dict(db.execute("SELECT * FROM scan_jobs WHERE id=?", (row["id"],)).fetchone())

    def locked_until(self, instant: datetime | None = None) -> datetime | None:
        """Latest expiry among live tenancy leases that keep queued scans waiting."""
        instant = instant or now()
        with self.store.db() as db:
            row = db.execute(
                "SELECT MAX(expires) FROM leases WHERE expires>?", (instant.isoformat(),)
            ).fetchone()
        return datetime.fromisoformat(row[0]) if row and row[0] else None

    def renew(self, generation: int, ident: str, owner: str) -> None:
        """Renew only an active job still owned by this worker and organization."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            db.execute(
                "UPDATE scan_jobs SET lease_expires=? WHERE id=? AND owner=? AND status='running'",
                ((now() + timedelta(seconds=120)).isoformat(), ident, owner),
            )

    def details(
        self, generation: int, ident: str
    ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Read a job and its immutable coverage snapshot within the active organization."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            job = db.execute(
                "SELECT * FROM scan_jobs WHERE id=? AND generation=?", (ident, generation)
            ).fetchone()
            if job is None:
                return None
            rows = db.execute(
                "SELECT data FROM scan_scope_results WHERE job_id=? ORDER BY scope", (ident,)
            ).fetchall()
        return dict(job), [json.loads(row[0]) for row in rows]

    def finish(self, generation: int, ident: str, owner: str, status: str, error: str = "") -> None:
        """Finish an owned job and atomically snapshot its coverage; stale owners cannot publish."""
        with self.store.db() as db:
            self.store.fence(db, generation)
            updated = db.execute(
                "UPDATE scan_jobs SET status=?,finished_at=?,error=? "
                "WHERE id=? AND owner=? AND status='running' AND lease_expires>?",
                (status, now().isoformat(), error, ident, owner, now().isoformat()),
            )
            if updated.rowcount:
                coverage = db.execute("SELECT * FROM coverage").fetchall()
                db.executemany(
                    "INSERT INTO scan_scope_results VALUES(?,?,?)",
                    [(ident, row["scope"], json.dumps(dict(row))) for row in coverage],
                )
