"""SQLite connection handling (docs/storage.md §4).

* WAL mode, foreign keys, busy timeout, incremental auto-vacuum.
* ``synchronous=NORMAL`` for replayable writes; ``write(durable=True)`` uses ``FULL`` for audit
  batches, checkpoints, migrations and organization state (docs/storage.md §4).
* One writer per database file: writes are serialized with a per-path lock; readers open
  separate read-only connections and are never blocked by WAL writers.
* Files are created with 0600 inside a 0700 directory.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

MIN_SQLITE = (3, 38, 0)  # built-in JSON functions (3.38) and STRICT tables (3.37)

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


class SqliteVersionError(RuntimeError):
    pass


def check_sqlite_version() -> None:
    version = tuple(int(p) for p in sqlite3.sqlite_version.split("."))
    if version < MIN_SQLITE:
        raise SqliteVersionError(
            f"SQLite {sqlite3.sqlite_version} is too old; OSC needs >= "
            + ".".join(map(str, MIN_SQLITE))
        )


def _writer_lock(path: Path) -> threading.Lock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[key] = lock
        return lock


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


class SqliteDatabase:
    """A single SQLite file with OSC's pragmas and a serialized write path."""

    def __init__(self, path: Path, schema: str | None = None) -> None:
        check_sqlite_version()
        self.path = path
        ensure_private_dir(path.parent)
        is_new = not path.exists()
        if is_new:
            # Create with restrictive permissions before SQLite opens it.
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        os.chmod(path, 0o600)
        with self._open(readonly=False) as conn:
            if is_new:
                conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
                conn.execute("VACUUM")  # auto_vacuum only takes effect on an empty DB after VACUUM
            conn.execute("PRAGMA journal_mode=WAL")
            if schema:
                conn.executescript(schema)

    @contextmanager
    def _open(self, readonly: bool) -> Iterator[sqlite3.Connection]:
        if readonly:
            conn = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, timeout=5.0, check_same_thread=False
            )
        else:
            conn = sqlite3.connect(self.path, timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        if not readonly:
            conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def write(self, durable: bool = False) -> Iterator[sqlite3.Connection]:
        """Serialized write transaction. Commits on success, rolls back on error.

        ``durable=True`` commits with ``synchronous=FULL`` so the commit survives power loss
        before anything that depends on it (a checkpoint, a generation change) is written.
        """
        with _writer_lock(self.path), self._open(readonly=False) as conn:
            if durable:
                conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.rollback()
                raise
            else:
                conn.commit()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        with self._open(readonly=True) as conn:
            yield conn

    def incremental_vacuum(self) -> None:
        with _writer_lock(self.path), self._open(readonly=False) as conn:
            conn.execute("PRAGMA incremental_vacuum")

    def quick_check(self) -> bool:
        with self.read() as conn:
            row = conn.execute("PRAGMA quick_check").fetchone()
            return bool(row and row[0] == "ok")

    def backup_to(self, dest: Path) -> None:
        ensure_private_dir(dest.parent)
        with self.read() as src:
            target = sqlite3.connect(dest)
            try:
                src.backup(target)
            finally:
                target.close()
        os.chmod(dest, 0o600)
