"""Storage errors. All of them mean "nothing was written"."""

from __future__ import annotations


class StorageError(RuntimeError):
    pass


class SchemaError(StorageError):
    """The database schema is newer than this OSC, or doesn't match the dataset registry."""


class StaleGenerationError(StorageError):
    """The caller started under an older organization generation (docs/control-plane.md §6.1)."""


class MaintenanceError(StorageError):
    """An exclusive maintenance operation (organization switch, restore) holds the barrier."""


class LeaseError(StorageError):
    """The caller's scope lease is missing, expired or held by someone else."""


class ScopeError(StorageError):
    """Records or a manifest don't match the declared collection scope."""


class IncompleteSnapshotError(StorageError):
    """Only a complete manifest may replace current rows (docs/storage.md §4.1)."""


class StaleRunError(StorageError):
    """An older run tried to replace a snapshot that a newer run already published."""
