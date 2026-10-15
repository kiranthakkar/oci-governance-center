"""Read-only SDK boundary (docs/architecture.md §3).

Runtime: every client from ``ClientFactory`` is a ``ReadOnlyClient`` that only exposes the reviewed
read operations of its own client class.

Static (over ``src/``):
* every attribute named like an OCI SDK operation is either allow-listed or a local method exempted
  for one specific file + receiver (local exemptions are receiver-specific, not name-wide);
* the allow-list has no stale entries and nothing uses an unlisted SDK operation;
* SDK objects are constructed only in the client factory and the signer factory;
* no SDK bypass attributes (``base_client``, ``call_api``) or wrapped-client internals;
* dynamic ``getattr``/``setattr`` and ``__dict__``-style dispatch only at reviewed sites;
* raw HTTP only in the reviewed OIDC code (token refresh + userinfo); OIDC flows via authlib.
No test makes a live OCI call.
"""

from __future__ import annotations

import ast
import functools
import importlib
import inspect
import pkgutil
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import oci
import pytest

from oci_security_center.auth.signers import OciAuth
from oci_security_center.models import ConnectionMethod
from oci_security_center.oci_clients import ClientFactory
from oci_security_center.oci_clients.allowlist import (
    READ_OPERATIONS,
    ReadOnlyClient,
    ReadOnlyViolation,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "oci_security_center"
ALLOWED = frozenset().union(*READ_OPERATIONS.values())

# Local methods whose names collide with OCI SDK operation names, exempt only on these receivers.
LOCAL_RECEIVERS: dict[tuple[str, str, str], str] = {
    ("storage/sqlite/db.py", "conn", "close"): "sqlite3 connection",
    ("storage/sqlite/db.py", "target", "close"): "sqlite3 backup target",
    ("storage/sqlite/db.py", "os", "close"): "file descriptor",
    ("auth/secrets.py", "self._fernet", "encrypt"): "Fernet",
    ("auth/secrets.py", "self._fernet", "decrypt"): "Fernet",
    ("web/sessions.py", "self.crypto", "encrypt"): "SecretResolver",
    ("web/sessions.py", "self.crypto", "decrypt"): "SecretResolver",
    ("web/sessions.py", "self.store", "get_session"): "OSC session store",
    ("web/sessions.py", "self.store", "delete_session"): "OSC session store",
    ("control_plane/service.py", "self.state", "get_connection"): "OSC app-state store",
    ("control_plane/service.py", "self.state", "get_setting"): "OSC app-state store",
    ("control_plane/service.py", "self.state", "get_tenancy"): "OSC app-state store",
    ("web/app.py", "cp.state", "get_setting"): "OSC app-state store",
    ("web/app.py", "cp.state", "get_tenancy"): "OSC app-state store",
    ("web/app.py", "cp.state", "list_events"): "OSC control-plane audit trail",
    ("web/app.py", "rt.stores.data", "list_findings"): "OSC data store",
    ("cli.py", "rt.stores.data", "list_findings"): "OSC data store",
    ("web/dashboards.py", "rt.stores.data", "list_findings"): "OSC data store",
    ("cli.py", "uvicorn", "run"): "ASGI server",
    ("storage/sqlite/backup.py", "os", "close"): "file descriptor",
    ("storage/sqlite/backup.py", "source", "close"): "sqlite3 connection",
    ("storage/sqlite/backup.py", "target", "close"): "sqlite3 connection",
    ("storage/sqlite/backup.py", "conn", "close"): "sqlite3 connection",
    ("storage/sqlite/backup.py", "cipher", "encrypt"): "Fernet",
    ("storage/sqlite/backup.py", "cipher", "decrypt"): "Fernet",
}

# Modules that may construct SDK objects (``oci.<...>(...)``): reviewed infrastructure.
SDK_CONSTRUCTION = {"oci_clients/__init__.py", "auth/signers.py"}
# The boundary itself is the only place that may reach into the wrapped client dynamically.
BOUNDARY = "oci_clients/allowlist.py"
FORBIDDEN_ATTRIBUTES = {
    "base_client",
    "call_api",
    "__dict__",
    "__getattribute__",
    "_ReadOnlyClient__client",
    "_ReadOnlyClient__allowed",
}
# Reviewed dynamic attribute access with a non-constant name: (file, receiver).
DYNAMIC_ATTRIBUTE_SITES = {
    ("models/collection.py", "self"),  # CollectionScope dimension lookup
    ("storage/sqlite/data_store.py", "env"),  # Envelope dimension lookup
}
FORBIDDEN_MODULES = (
    "requests",
    "urllib.request",
    "urllib3",
    "http.client",
    "aiohttp",
    "socket",
    "pycurl",
    "oci._vendor",
    "oci.base_client",
)
RESTRICTED_MODULES = {"httpx": {"web/security.py"}, "authlib": {"web/app.py"}}
# Reviewed raw HTTP: (file, enclosing function, call). OIDC token refresh and userinfo only.
HTTP_CALLS = {
    ("web/security.py", "jwt_provider_for", "httpx.post"),
    ("web/security.py", "_current_role", "httpx.get"),
}


@functools.cache
def sdk_operation_names() -> frozenset[str]:
    """Every public method of every OCI SDK client class (plus the base client)."""
    names: set[str] = {
        n
        for n, f in vars(oci.base_client.BaseClient).items()
        if callable(f) and not n.startswith("_")
    }
    for info in pkgutil.iter_modules(oci.__path__):
        try:
            module = importlib.import_module(f"oci.{info.name}")
        except Exception:  # optional SDK modules with extra dependencies
            continue
        for name, obj in vars(module).items():
            if (
                inspect.isclass(obj)
                and name.endswith("Client")
                and obj.__module__.startswith("oci")
            ):
                names |= {n for n, f in vars(obj).items() if callable(f) and not n.startswith("_")}
    return frozenset(names)


@dataclass
class Report:
    violations: list[str] = field(default_factory=list)
    sdk_ops_used: set[str] = field(default_factory=set)
    exemptions_used: set[tuple[str, str, str]] = field(default_factory=set)
    http_calls: set[tuple[str, str, str]] = field(default_factory=set)


def _dotted(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover
        return "?"


def _functions(tree: ast.AST) -> Iterator[tuple[ast.AST, str]]:
    """Yield (node, enclosing top-level function name) for every node."""
    for top in ast.iter_child_nodes(tree):
        name = top.name if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)) else ""
        for node in ast.walk(top):
            yield node, name


def scan(rel: str, source: str, report: Report) -> None:
    ops = sdk_operation_names()
    tree = ast.parse(source)
    for node, func in _functions(tree):
        if isinstance(node, ast.Attribute):
            receiver = _dotted(node.value)
            where = f"{rel}:{node.lineno} {receiver}.{node.attr}"
            if node.attr in FORBIDDEN_ATTRIBUTES and rel != BOUNDARY:
                report.violations.append(f"{where}: SDK bypass / internals")
            elif node.attr in ops:
                key = (rel, receiver, node.attr)
                if key in LOCAL_RECEIVERS:
                    report.exemptions_used.add(key)
                elif node.attr in ALLOWED:
                    report.sdk_ops_used.add(node.attr)
                else:
                    report.violations.append(f"{where}: not an allow-listed read operation")
        elif isinstance(node, ast.Call):
            callee = _dotted(node.func)
            if callee.startswith("oci.") and rel not in SDK_CONSTRUCTION:
                report.violations.append(f"{rel}:{node.lineno} {callee}(): SDK use outside factory")
            if callee in ("getattr", "setattr", "delattr", "hasattr") and rel != BOUNDARY:
                target, name = node.args[0], node.args[1] if len(node.args) > 1 else None
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    if name.value in ops and name.value not in ALLOWED:
                        report.violations.append(f"{rel}:{node.lineno} {callee} of {name.value}")
                elif (rel, _dotted(target)) not in DYNAMIC_ATTRIBUTE_SITES:
                    report.violations.append(f"{rel}:{node.lineno} dynamic {callee}")
            if callee.split(".")[0] in ("httpx", "requests", "urllib3", "aiohttp"):
                key = (rel, func, callee)
                if key in HTTP_CALLS:
                    report.http_calls.add(key)
                else:
                    report.violations.append(f"{rel}:{node.lineno} raw HTTP {callee}")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            modules = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            if isinstance(node, ast.ImportFrom) and node.module == "oci":
                modules = [f"oci.{a.name}" for a in node.names]
            for mod in modules:
                if any(mod == f or mod.startswith(f + ".") for f in FORBIDDEN_MODULES):
                    report.violations.append(f"{rel}:{node.lineno} import {mod}")
                for restricted, allowed_in in RESTRICTED_MODULES.items():
                    if (mod == restricted or mod.startswith(restricted + ".")) and (
                        rel not in allowed_in
                    ):
                        report.violations.append(f"{rel}:{node.lineno} import {mod}")


@functools.cache
def src_report() -> Report:
    report = Report()
    for path in sorted(SRC.rglob("*.py")):
        scan(path.relative_to(SRC).as_posix(), path.read_text(), report)
    return report


# --- static checks on src/ -----------------------------------------------------------------------
def test_src_has_no_boundary_violations() -> None:
    assert src_report().violations == []


def test_allow_list_matches_actual_use() -> None:
    report = src_report()
    assert report.sdk_ops_used == ALLOWED, (
        f"stale allow-list entries: {sorted(ALLOWED - report.sdk_ops_used)}; "
        f"unlisted: {sorted(report.sdk_ops_used - ALLOWED)}"
    )


def test_local_exemptions_are_all_needed() -> None:
    assert set(LOCAL_RECEIVERS) == src_report().exemptions_used


def test_reviewed_http_calls_are_the_only_ones() -> None:
    assert src_report().http_calls == HTTP_CALLS


def test_allow_list_is_reads_only() -> None:
    for cls, names in READ_OPERATIONS.items():
        for name in names:
            assert name.startswith(("get_", "list_", "summarize_", "search_")), (cls, name)
            assert callable(getattr(cls, name)), (cls, name)


# --- the detector catches each bypass shape ------------------------------------------------------
@pytest.mark.parametrize(
    ("rel", "source", "expected"),
    [
        ("collectors/x.py", "identity.delete_policy(p)", "not an allow-listed"),
        ("collectors/x.py", "f = identity.create_policy\nf(p)", "not an allow-listed"),
        ("collectors/x.py", "getattr(identity, 'update_policy')(p)", "getattr of update_policy"),
        ("collectors/x.py", "getattr(identity, name)(p)", "dynamic getattr"),
        ("collectors/x.py", "identity.base_client.call_api('POST')", "SDK bypass"),
        ("collectors/x.py", "c._ReadOnlyClient__client.delete_policy(p)", "SDK bypass"),
        ("collectors/x.py", "c.__dict__['x']", "SDK bypass"),
        ("collectors/x.py", "oci.identity.IdentityClient(cfg)", "SDK use outside factory"),
        ("collectors/x.py", "from oci import base_client", "import oci.base_client"),
        ("collectors/x.py", "import requests\nrequests.post(u)", "import requests"),
        ("collectors/x.py", "from oci._vendor import requests", "import oci._vendor"),
        ("collectors/x.py", "import httpx", "import httpx"),
        ("web/security.py", "def other():\n    httpx.post(u)", "raw HTTP httpx.post"),
        # a local exemption is receiver-specific: same method name, other receiver
        ("web/sessions.py", "self.other.delete_session(x)", "not an allow-listed"),
        ("web/app.py", "self.store.delete_session(x)", "not an allow-listed"),
    ],
)
def test_detector_flags_bypass(rel: str, source: str, expected: str) -> None:
    report = Report()
    scan(rel, source, report)
    assert any(expected in v for v in report.violations), report.violations


def test_detector_allows_reviewed_patterns() -> None:
    report = Report()
    scan("web/sessions.py", "self.store.delete_session(h)", report)
    scan("collectors/x.py", "list_all(identity.list_policies, c)", report)
    assert report.violations == []


# --- runtime boundary ----------------------------------------------------------------------------
class _OfflineSigner(oci.auth.signers.SecurityTokenSigner):  # type: ignore[misc]
    """Lets SDK clients be constructed without credentials or network."""

    def __init__(self) -> None:
        pass


def _factory() -> ClientFactory:
    auth = OciAuth(
        {"region": "us-ashburn-1"}, _OfflineSigner(), None, "us-ashburn-1", ConnectionMethod.API_KEY
    )
    return ClientFactory(auth)


def test_allowed_read_reaches_the_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        oci.identity.IdentityClient,
        "list_policies",
        lambda self, compartment_id, **_: calls.append(compartment_id) or "ok",
    )
    client: Any = _factory()(oci.identity.IdentityClient, "eu-frankfurt-1")
    assert isinstance(client, ReadOnlyClient)
    alias = client.list_policies  # aliasing an allowed read is fine
    assert alias("ocid1.tenancy.oc1..aaaafake") == "ok"
    assert calls == ["ocid1.tenancy.oc1..aaaafake"]
    assert dir(client) == sorted(READ_OPERATIONS[oci.identity.IdentityClient])


def test_mutating_and_unknown_attributes_never_reach_the_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reached: list[str] = []
    monkeypatch.setattr(
        oci.identity.IdentityClient, "delete_policy", lambda *a, **k: reached.append("x")
    )
    client: Any = _factory()(oci.identity.IdentityClient)
    for name in ("delete_policy", "create_policy", "base_client", "update_tag_namespace"):
        with pytest.raises(ReadOnlyViolation):
            getattr(client, name)
    with pytest.raises(ReadOnlyViolation):
        client.get_secret_bundle  # noqa: B018 - allowed for SecretsClient, not this client
    with pytest.raises(ReadOnlyViolation):
        client.list_policies = lambda *a: None
    with pytest.raises(ReadOnlyViolation):
        del client.list_policies
    assert reached == []


def test_unreviewed_clients_are_never_constructed(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[str] = []
    monkeypatch.setattr(oci.core.ComputeClient, "__init__", lambda *a, **k: built.append("x"))
    with pytest.raises(ReadOnlyViolation, match="not a reviewed OCI client"):
        _factory()(oci.core.ComputeClient)
    with pytest.raises(ReadOnlyViolation):
        _factory()(lambda config, **kw: object())  # type: ignore[arg-type,return-value]
    assert built == []


def test_verify_step_does_not_swallow_violations() -> None:
    from oci_security_center.control_plane.verify import _step

    def bad() -> str:
        raise ReadOnlyViolation("x")

    with pytest.raises(ReadOnlyViolation):
        _step("probe", bad)
