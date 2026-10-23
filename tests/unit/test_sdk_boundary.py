"""Static SDK surface audit supplements runtime allow-lists and bypass tests."""

import ast
from pathlib import Path

from oci_governance_center.oci_clients import OPERATIONS

ROOT = Path(__file__).resolve().parents[2] / "src" / "oci_governance_center"


def test_sdk_construction_and_http_are_confined_to_reviewed_modules():
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                name = ast.unparse(node.func)
                if name.startswith("oci.") and name.endswith("Client"):
                    assert relative == "oci_clients/__init__.py", (relative, name)
                if name.startswith("oci.") and name.endswith(("Signer", "TokenExchangeSigner")):
                    assert relative == "auth/scanner.py", (relative, name)
                if name.startswith(("requests.", "httpx.")):
                    assert relative in {"auth/scanner.py", "auth/oidc.py"}, (relative, name)
                if node.func.attr in {"base_client", "call_api"}:
                    raise AssertionError((relative, "SDK bypass"))


def test_allowlist_matches_operations_referenced_by_collection_and_binding():
    references = set()
    for path in ROOT.rglob("*.py"):
        if path.parent.name == "oci_clients":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr.startswith(
                ("get_", "list_", "search_", "summarize_")
            ):
                # Receiver-specific local methods: storage candidate access and secret unwrapping.
                if node.attr == "get_secret_value":
                    continue
                if node.attr == "get_candidate" and ast.unparse(node.value) in {
                    "store",
                    "self.store",
                }:
                    continue
                references.add(node.attr)
    allowed = set().union(*OPERATIONS.values())
    assert references == allowed, (references - allowed, allowed - references)
