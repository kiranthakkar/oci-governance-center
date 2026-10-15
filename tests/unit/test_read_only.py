"""OSC is strictly read-only against OCI (AGENTS.md §2.1) — supplementary deny-list guard.

The primary enforcement is the explicit allow-list boundary (``oci_clients/allowlist.py``,
``tests/unit/test_sdk_boundary.py``); this older check stays as a second, independent guard.

Static check over ``src/``: any method call whose name starts with a mutating verb fails the build,
unless it is one of OSC's *own* storage/service methods listed below (which never touch OCI).
Adding to this allow-list requires review: it must not be an OCI SDK method.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "oci_security_center"

MUTATING = re.compile(
    r"^(create|update|delete|change|move|approve|unapprove|restore|put|patch|terminate|launch|"
    r"activate|deactivate|cancel|enable|disable|remove|add|attach|detach|reset|rotate|schedule|"
    r"upload|bulk|import|export|recover|replace|install|uninstall|start|stop|reboot|"
    r"instance_action|apply|execute|run|trigger|purge|set|post)_"
)

# OSC's own methods (SQLite store / control plane), never OCI SDK calls.
OWN_METHODS = {
    "put_session",
    "delete_session",
    "put_secret_ciphertext",
    "delete_secret_ciphertext",
    "activate_child",
    "set_setting",
    "set_watermark",
    "set_admin_browse",
    "set_organization_parent",
    "apply_snapshot",
    "upsert_tenancy",
    "upsert_findings",
    "add_middleware",
    "add_typer",
    "set_cookie",
    "create_client",  # Authlib in-process OAuth client registry, not OCI
}

# Plain HTTP writes are only allowed for the OIDC token refresh against the identity domain.
HTTP_WRITE_ALLOWED = {"web/security.py"}


def _calls(tree: ast.AST) -> list[tuple[str, str, int]]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            owner_name = owner.id if isinstance(owner, ast.Name) else ""
            out.append((owner_name, node.func.attr, node.lineno))
    return out


def test_no_mutating_oci_calls() -> None:
    offenders = []
    for path in SRC.rglob("*.py"):
        rel = path.relative_to(SRC).as_posix()
        for owner, attr, line in _calls(ast.parse(path.read_text())):
            if MUTATING.match(attr) and attr not in OWN_METHODS:
                offenders.append(f"{rel}:{line} {owner}.{attr}")
            if (
                owner in ("requests", "httpx")
                and attr in ("post", "put", "patch", "delete")
                and rel not in HTTP_WRITE_ALLOWED
            ):
                offenders.append(f"{rel}:{line} {owner}.{attr}")
    assert not offenders, "mutating calls found:\n" + "\n".join(offenders)


def test_detector_catches_sdk_write() -> None:
    sample = "identity.create_policy(details)\norg_client.create_child_tenancy(x)\n"
    found = [a for _, a, _ in _calls(ast.parse(sample)) if MUTATING.match(a)]
    assert found == ["create_policy", "create_child_tenancy"]
