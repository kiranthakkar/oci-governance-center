"""Operator entry points; provisioning remains an administrator action outside OGC."""

from __future__ import annotations

import os
import signal
import threading
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from cryptography.fernet import Fernet

from .config import Settings
from .logging import configure_logging
from .provisioning.bundle import bundle
from .scans import ScanControl
from .scheduler import ScanWorker
from .service import Service
from .storage import Store

app = typer.Typer(help="OCI Governance Center — read-only organization governance")


def runtime() -> tuple[Settings, Service]:
    """Construct the shared local runtime without contacting OCI until a collection is requested."""
    configure_logging()
    settings = Settings()  # type: ignore[call-arg]  # required secrets are provided through environment
    store = Store(settings.data_root, settings.encryption_key.get_secret_value())
    return settings, Service(settings, store)


@app.command()
def encryption_key() -> None:
    """Generate an operator encryption key; retain separately from the database and backups."""
    typer.echo(Fernet.generate_key().decode())


@app.command()
def web(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Serve OGC over loopback HTTP for development or behind an HTTPS reverse proxy."""
    from .web.app import create_app

    settings, service = runtime()
    uvicorn.run(
        create_app(settings, service),
        host=host,
        port=port,
        proxy_headers=False,
        access_log=False,
        log_config=None,
    )


@app.command()
def scan(
    family: Annotated[str, typer.Option(help="all, identity, governance, or audit")] = "all",
) -> None:
    """Collect using parent API key or child UPST only; requires the local read policy templates."""
    _, service = runtime()
    service.scan(family)
    if family == "all":
        service.scan("audit")


@app.command()
def scheduler(once: bool = False) -> None:
    """Run collection separately; never start it in web workers."""
    settings, service = runtime()
    worker = ScanWorker(service)
    stop = threading.Event()

    def request_stop(*_: Any) -> None:
        # First signal: stop at the next safe point (after the current OCI request) and mark the
        # job interrupted. Second signal: mark it interrupted, release this worker's tenancy
        # locks and exit at once. Messages go straight to stderr: logging is not re-entrant.
        if stop.is_set():
            os.write(2, b"Second stop signal; exiting immediately\n")
            try:
                worker.abandon()
            finally:
                os._exit(130)
        os.write(
            2,
            b"Stopping: the current scan ends after its current OCI request. "
            b"Press Ctrl-C again to exit immediately.\n",
        )
        stop.set()
        service.stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    if once:
        generation = service.store.state()[0]
        ScanControl(service.store).enqueue(generation, "cli", "cli")
        worker.run_once()
        return
    worker.run(stop)


@app.command()
def purge() -> None:
    """Apply configured local retention without any OCI calls."""
    settings, service = runtime()
    service.store.purge(settings.retention_days)


@app.command()
def setup_package(kind: str, output: Path) -> None:
    """Write an administrator-applied parent or child setup ZIP without any credentials."""
    if kind not in {"parent", "child"}:
        raise typer.BadParameter("Choose parent or child")
    output.write_bytes(bundle(kind))  # type: ignore[arg-type]
    typer.echo(f"Created {output}")
