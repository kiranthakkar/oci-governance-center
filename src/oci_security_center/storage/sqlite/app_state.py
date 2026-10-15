"""SQLite implementation of :class:`AppStateStore` (``osc.db``)."""

from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from oci_security_center.models import (
    CheckStatus,
    Connection,
    ConnectionMethod,
    ConnectionPurpose,
    OnboardingStatus,
    OrgRole,
    RequirementCheck,
    Tenancy,
)
from oci_security_center.models.common import iso, utcnow
from oci_security_center.storage.errors import MaintenanceError
from oci_security_center.storage.sqlite.db import SqliteDatabase
from oci_security_center.storage.sqlite.fence import check_fence


@dataclass(frozen=True)
class OrganizationState:
    generation: int
    parent_tenancy_ocid: str | None
    state: str  # active | maintenance
    maintenance_holder: str | None
    maintenance_expires_at: datetime | None


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _opt_iso(value: datetime | None) -> str | None:
    return iso(value) if value else None


class SqliteAppStateStore:
    def __init__(self, db: SqliteDatabase) -> None:
        self.db = db

    # --- settings -------------------------------------------------------------------------
    def get_setting(self, key: str) -> str | None:
        with self.db.read() as conn:
            row = conn.execute("SELECT value FROM settings_kv WHERE key=?", (key,)).fetchone()
            return str(row["value"]) if row else None

    def set_setting(self, key: str, value: str, generation: int | None = None) -> None:
        """``generation``: fence the write to the organization the caller started under."""
        with self.db.write() as conn:
            if generation is not None:
                check_fence(conn, generation)
            conn.execute(
                "INSERT INTO settings_kv(key, value, updated_at) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
                "updated_at=excluded.updated_at",
                (key, value, iso(utcnow())),
            )

    # --- organization generation and maintenance barrier ------------------------------------
    def organization(self) -> OrganizationState:
        with self.db.read() as conn:
            row = conn.execute("SELECT * FROM organization_state WHERE id=1").fetchone()
        return OrganizationState(
            int(row["generation"]),
            row["parent_tenancy_ocid"],
            row["state"],
            row["maintenance_holder"],
            _dt(row["maintenance_expires_at"]),
        )

    def current_generation(self) -> int:
        return self.organization().generation

    def set_organization_parent(self, parent_ocid: str, generation: int) -> None:
        """Record the parent for the current generation (first bootstrap; no switch)."""
        with self.db.write(durable=True) as conn:
            check_fence(conn, generation)
            conn.execute(
                "UPDATE organization_state SET parent_tenancy_ocid=?, updated_at=? WHERE id=1",
                (parent_ocid, iso(utcnow())),
            )

    def begin_maintenance(self, holder: str, ttl_seconds: int = 600) -> str:
        """Take the exclusive side of the barrier. Fenced writes fail until it ends.

        An expired maintenance lease (its holder crashed) may be taken over, so the new holder
        can finish or roll back the interrupted operation.
        """
        token = secrets.token_hex(16)
        now = utcnow()
        with self.db.write(durable=True) as conn:
            row = conn.execute(
                "SELECT state, maintenance_expires_at FROM organization_state WHERE id=1"
            ).fetchone()
            if row["state"] == "maintenance" and row["maintenance_expires_at"] > iso(now):
                raise MaintenanceError("another maintenance operation is in progress")
            conn.execute(
                "UPDATE organization_state SET state='maintenance', maintenance_token=?, "
                "maintenance_holder=?, maintenance_expires_at=?, updated_at=? WHERE id=1",
                (token, holder, iso(now + timedelta(seconds=ttl_seconds)), iso(now)),
            )
        return token

    def end_maintenance(
        self, token: str, advance_generation: bool = False, parent_ocid: str | None = None
    ) -> int:
        """Release the barrier; optionally start a new organization generation."""
        with self.db.write(durable=True) as conn:
            return self.end_maintenance_in(conn, token, advance_generation, parent_ocid)

    @staticmethod
    def end_maintenance_in(
        conn: sqlite3.Connection,
        token: str,
        advance_generation: bool = False,
        parent_ocid: str | None = None,
    ) -> int:
        """``end_maintenance`` inside a caller's transaction (switch + cleanup commit together)."""
        row = conn.execute(
            "SELECT generation, parent_tenancy_ocid, state, maintenance_token "
            "FROM organization_state WHERE id=1"
        ).fetchone()
        if row["state"] != "maintenance" or row["maintenance_token"] != token:
            raise MaintenanceError("maintenance is not held by this token")
        generation = int(row["generation"]) + (1 if advance_generation else 0)
        conn.execute(
            "UPDATE organization_state SET state='active', generation=?, parent_tenancy_ocid=?, "
            "maintenance_token=NULL, maintenance_holder=NULL, maintenance_expires_at=NULL, "
            "updated_at=? WHERE id=1",
            (generation, parent_ocid or row["parent_tenancy_ocid"], iso(utcnow())),
        )
        if advance_generation:
            conn.execute("DELETE FROM scope_leases")  # every old-generation lease is void
        return generation

    @staticmethod
    def advance_generation_in(conn: sqlite3.Connection, token: str, parent_ocid: str) -> int:
        """Advance the generation while *staying* in maintenance (switch commit, §6.1 step 4)."""
        row = conn.execute(
            "SELECT generation, state, maintenance_token FROM organization_state WHERE id=1"
        ).fetchone()
        if row["state"] != "maintenance" or row["maintenance_token"] != token:
            raise MaintenanceError("maintenance is not held by this token")
        generation = int(row["generation"]) + 1
        conn.execute(
            "UPDATE organization_state SET generation=?, parent_tenancy_ocid=?, updated_at=? "
            "WHERE id=1",
            (generation, parent_ocid, iso(utcnow())),
        )
        conn.execute("DELETE FROM scope_leases")
        return generation

    def active_leases(self) -> int:
        """Unexpired scope leases, i.e. collection still in flight."""
        with self.db.read() as conn:
            return int(
                conn.execute(
                    "SELECT COUNT(*) FROM scope_leases WHERE expires_at > ?", (iso(utcnow()),)
                ).fetchone()[0]
            )

    def revoke_all_leases(self) -> None:
        """Fence all in-flight collection (their commits fail with LeaseError)."""
        with self.db.write(durable=True) as conn:
            conn.execute("DELETE FROM scope_leases")

    # --- capability status (collection §10, control-plane §2.6) -----------------------------
    def record_capability(
        self,
        generation: int,
        tenancy_ocid: str,
        capability: str,
        scope_key: str,
        status: str,
        detail: str = "",
    ) -> None:
        with self.db.write() as conn:
            check_fence(conn, generation)
            conn.execute(
                "INSERT INTO capabilities (generation, tenancy_ocid, capability, scope_key, "
                "status, detail, checked_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(generation, "
                "tenancy_ocid, capability, scope_key) DO UPDATE SET status=excluded.status, "
                "detail=excluded.detail, checked_at=excluded.checked_at",
                (generation, tenancy_ocid, capability, scope_key, status, detail, iso(utcnow())),
            )

    def capabilities(
        self, generation: int, tenancy_ocid: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM capabilities WHERE generation=?"
        params: list[Any] = [generation]
        if tenancy_ocid:
            sql += " AND tenancy_ocid=?"
            params.append(tenancy_ocid)
        with self.db.read() as conn:
            return [
                dict(r) for r in conn.execute(sql + " ORDER BY tenancy_ocid, capability", params)
            ]

    def mark_capabilities_untested(self, generation: int) -> None:
        """Mark every capability untested (principal, policy or region change; §2.6)."""
        with self.db.write() as conn:
            check_fence(conn, generation)
            conn.execute(
                "UPDATE capabilities SET status='untested', detail='recheck required', "
                "checked_at=? WHERE generation=?",
                (iso(utcnow()), generation),
            )

    # --- scope leases (one active run per collection scope) --------------------------------
    def acquire_lease(
        self, lease_key: str, generation: int, holder: str, ttl_seconds: int = 900
    ) -> str | None:
        """Return a lease token, or None while another unexpired lease holds the scope."""
        token = secrets.token_hex(16)
        now = utcnow()
        with self.db.write() as conn:
            check_fence(conn, generation)
            row = conn.execute(
                "SELECT expires_at FROM scope_leases WHERE lease_key=?", (lease_key,)
            ).fetchone()
            if row is not None and row["expires_at"] > iso(now):
                return None
            conn.execute(
                "INSERT INTO scope_leases (lease_key, generation, token, holder, acquired_at, "
                "expires_at) VALUES (?,?,?,?,?,?) ON CONFLICT(lease_key) DO UPDATE SET "
                "generation=excluded.generation, token=excluded.token, holder=excluded.holder, "
                "acquired_at=excluded.acquired_at, expires_at=excluded.expires_at",
                (
                    lease_key,
                    generation,
                    token,
                    holder,
                    iso(now),
                    iso(now + timedelta(seconds=ttl_seconds)),
                ),
            )
        return token

    def renew_lease(self, lease_key: str, token: str, ttl_seconds: int = 900) -> bool:
        now = utcnow()
        with self.db.write() as conn:
            return (
                conn.execute(
                    "UPDATE scope_leases SET expires_at=? WHERE lease_key=? AND token=? "
                    "AND expires_at > ?",
                    (iso(now + timedelta(seconds=ttl_seconds)), lease_key, token, iso(now)),
                ).rowcount
                == 1
            )

    def release_lease(self, lease_key: str, token: str) -> None:
        with self.db.write() as conn:
            conn.execute(
                "DELETE FROM scope_leases WHERE lease_key=? AND token=?", (lease_key, token)
            )

    # --- tenancies ------------------------------------------------------------------------
    def upsert_tenancy(self, tenancy: Tenancy, generation: int | None = None) -> None:
        with self.db.write() as conn:
            if generation is not None:
                check_fence(conn, generation)
            self.upsert_tenancy_in(conn, tenancy)

    @staticmethod
    def upsert_tenancy_in(conn: sqlite3.Connection, tenancy: Tenancy) -> None:
        """Write within the caller's fenced transaction."""
        conn.execute(
            """
            INSERT INTO tenancies (ocid, name, alias, org_role, home_region, subscribed_regions,
              organization_id, parent_tenancy_ocid, onboarding_status, status_detail,
              lifecycle_state, governance_status, last_verified_at, last_scanned_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ocid) DO UPDATE SET
              name=excluded.name, alias=excluded.alias, org_role=excluded.org_role,
              home_region=excluded.home_region, subscribed_regions=excluded.subscribed_regions,
              organization_id=excluded.organization_id,
              parent_tenancy_ocid=excluded.parent_tenancy_ocid,
              onboarding_status=excluded.onboarding_status,
              status_detail=excluded.status_detail, lifecycle_state=excluded.lifecycle_state,
              governance_status=excluded.governance_status,
              last_verified_at=excluded.last_verified_at,
              last_scanned_at=excluded.last_scanned_at, updated_at=excluded.updated_at
            """,
            (
                tenancy.ocid,
                tenancy.name,
                tenancy.alias,
                tenancy.org_role.value,
                tenancy.home_region,
                json.dumps(list(tenancy.subscribed_regions)),
                tenancy.organization_id,
                tenancy.parent_tenancy_ocid,
                tenancy.onboarding_status.value,
                tenancy.status_detail,
                tenancy.lifecycle_state,
                tenancy.governance_status,
                _opt_iso(tenancy.last_verified_at),
                _opt_iso(tenancy.last_scanned_at),
                iso(utcnow()),
            ),
        )

    @staticmethod
    def _row_to_tenancy(row: sqlite3.Row) -> Tenancy:
        return Tenancy(
            ocid=row["ocid"],
            name=row["name"],
            alias=row["alias"],
            org_role=OrgRole(row["org_role"]),
            home_region=row["home_region"],
            subscribed_regions=tuple(json.loads(row["subscribed_regions"])),
            organization_id=row["organization_id"],
            parent_tenancy_ocid=row["parent_tenancy_ocid"],
            onboarding_status=OnboardingStatus(row["onboarding_status"]),
            status_detail=row["status_detail"],
            lifecycle_state=row["lifecycle_state"],
            governance_status=row["governance_status"],
            last_verified_at=_dt(row["last_verified_at"]),
            last_scanned_at=_dt(row["last_scanned_at"]),
        )

    def get_tenancy(self, ocid: str) -> Tenancy | None:
        with self.db.read() as conn:
            row = conn.execute("SELECT * FROM tenancies WHERE ocid=?", (ocid,)).fetchone()
            return self._row_to_tenancy(row) if row else None

    def list_tenancies(self) -> list[Tenancy]:
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM tenancies "
                "ORDER BY CASE org_role WHEN 'PARENT' THEN 0 ELSE 1 END, name"
            ).fetchall()
            return [self._row_to_tenancy(r) for r in rows]

    # --- connections ----------------------------------------------------------------------
    def save_connection(self, connection: Connection, generation: int | None = None) -> None:
        with self.db.write() as conn:
            if generation is not None:
                check_fence(conn, generation)
            self.save_connection_in(conn, connection)

    @staticmethod
    def save_connection_in(conn: sqlite3.Connection, connection: Connection) -> None:
        """Write within the caller's fenced transaction."""
        c = connection
        conn.execute(
            """
            INSERT INTO connections (id, tenancy_ocid, method, purpose, region, domain_url,
              client_id, cli_config_path, cli_profile, user_ocid, fingerprint, secret_ref,
              created_by, created_at, last_tested_at, last_test_result)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(tenancy_ocid, purpose) DO UPDATE SET
              id=excluded.id, method=excluded.method, region=excluded.region,
              domain_url=excluded.domain_url, client_id=excluded.client_id,
              cli_config_path=excluded.cli_config_path, cli_profile=excluded.cli_profile,
              user_ocid=excluded.user_ocid, fingerprint=excluded.fingerprint,
              secret_ref=excluded.secret_ref, created_by=excluded.created_by,
              last_tested_at=excluded.last_tested_at, last_test_result=excluded.last_test_result
            """,
            (
                c.id,
                c.tenancy_ocid,
                c.method.value,
                c.purpose.value,
                c.region,
                c.domain_url,
                c.client_id,
                c.cli_config_path,
                c.cli_profile,
                c.user_ocid,
                c.fingerprint,
                c.secret_ref,
                c.created_by,
                iso(c.created_at or utcnow()),
                _opt_iso(c.last_tested_at),
                c.last_test_result,
            ),
        )

    def get_connection(self, tenancy_ocid: str, purpose: ConnectionPurpose) -> Connection | None:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT * FROM connections WHERE tenancy_ocid=? AND purpose=?",
                (tenancy_ocid, purpose.value),
            ).fetchone()
        if not row:
            return None
        return Connection(
            id=row["id"],
            tenancy_ocid=row["tenancy_ocid"],
            method=ConnectionMethod(row["method"]),
            purpose=ConnectionPurpose(row["purpose"]),
            region=row["region"],
            domain_url=row["domain_url"],
            client_id=row["client_id"],
            cli_config_path=row["cli_config_path"],
            cli_profile=row["cli_profile"],
            user_ocid=row["user_ocid"],
            fingerprint=row["fingerprint"],
            secret_ref=row["secret_ref"],
            created_by=row["created_by"],
            created_at=_dt(row["created_at"]),
            last_tested_at=_dt(row["last_tested_at"]),
            last_test_result=row["last_test_result"],
        )

    # --- local encrypted secrets (ciphertext only) -----------------------------------------
    def put_secret_ciphertext(self, secret_id: str, ciphertext: bytes) -> None:
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO local_secrets(id, ciphertext, created_at) VALUES (?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext",
                (secret_id, ciphertext, iso(utcnow())),
            )

    def delete_secret_ciphertext(self, secret_id: str) -> None:
        with self.db.write() as conn:
            conn.execute("DELETE FROM local_secrets WHERE id=?", (secret_id,))

    def get_secret_ciphertext(self, secret_id: str) -> bytes | None:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT ciphertext FROM local_secrets WHERE id=?", (secret_id,)
            ).fetchone()
            return bytes(row["ciphertext"]) if row else None

    # --- requirement checks ---------------------------------------------------------------
    def save_checks(
        self,
        tenancy_ocid: str,
        target_tenancy_ocid: str,
        checks: Sequence[RequirementCheck],
        generation: int | None = None,
    ) -> None:
        with self.db.write() as conn:
            if generation is not None:
                check_fence(conn, generation)
            conn.executemany(
                """
                INSERT INTO requirement_checks (requirement_id, tenancy_ocid, target_tenancy_ocid,
                  status, detail, matched_policy_ocid, matched_statement, checked_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(requirement_id) DO UPDATE SET status=excluded.status,
                  detail=excluded.detail, matched_policy_ocid=excluded.matched_policy_ocid,
                  matched_statement=excluded.matched_statement, checked_at=excluded.checked_at
                """,
                [
                    (
                        c.requirement_id,
                        tenancy_ocid,
                        target_tenancy_ocid,
                        c.status.value,
                        c.detail,
                        c.matched_policy_ocid,
                        c.matched_statement,
                        iso(c.checked_at or utcnow()),
                    )
                    for c in checks
                ],
            )

    def get_checks(self, requirement_ids: Sequence[str]) -> dict[str, RequirementCheck]:
        if not requirement_ids:
            return {}
        placeholders = ",".join("?" * len(requirement_ids))
        with self.db.read() as conn:
            rows = conn.execute(
                f"SELECT * FROM requirement_checks WHERE requirement_id IN ({placeholders})",  # noqa: S608
                tuple(requirement_ids),
            ).fetchall()
        return {
            r["requirement_id"]: RequirementCheck(
                requirement_id=r["requirement_id"],
                status=CheckStatus(r["status"]),
                detail=r["detail"],
                matched_policy_ocid=r["matched_policy_ocid"],
                matched_statement=r["matched_statement"],
                checked_at=_dt(r["checked_at"]),
            )
            for r in rows
        }

    # --- control-plane audit trail --------------------------------------------------------
    def record_event(
        self,
        actor: str,
        role: str,
        action: str,
        target: str | None,
        result: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO control_plane_events(at, actor, role, action, target, result, detail) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    iso(utcnow()),
                    actor,
                    role,
                    action,
                    target,
                    result,
                    json.dumps(detail or {}, default=str),
                ),
            )

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.read() as conn:
            rows = conn.execute(
                "SELECT * FROM control_plane_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # --- server-side sessions (encrypted blobs) -------------------------------------------
    def put_session(self, id_hash: str, data_enc: bytes, expires_at: datetime) -> None:
        now = iso(utcnow())
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO sessions(id_hash, data_enc, created_at, last_seen_at, expires_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(id_hash) DO UPDATE SET data_enc=excluded.data_enc, "
                "last_seen_at=excluded.last_seen_at, expires_at=excluded.expires_at",
                (id_hash, data_enc, now, now, iso(expires_at)),
            )

    def get_session(self, id_hash: str) -> bytes | None:
        with self.db.read() as conn:
            row = conn.execute(
                "SELECT data_enc FROM sessions WHERE id_hash=? AND expires_at > ?",
                (id_hash, iso(utcnow())),
            ).fetchone()
            return bytes(row["data_enc"]) if row else None

    def delete_session(self, id_hash: str) -> None:
        with self.db.write() as conn:
            conn.execute("DELETE FROM sessions WHERE id_hash=?", (id_hash,))

    def prune_expired_sessions(self) -> int:
        with self.db.write() as conn:
            return conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (iso(utcnow()),)
            ).rowcount
