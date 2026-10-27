"""Identity collection, fail-closed analysis scheduling and the Identity tab."""

import json
from collections import defaultdict
from datetime import timedelta
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import oci
import pytest

from oci_governance_center.collectors.inventory import read_api_keys, read_users
from oci_governance_center.models import Batch, Identity, Record, Scope, now
from oci_governance_center.oci_clients import all_items
from tests.conftest import install
from tests.unit.test_identity_analysis import identity_records
from tests.unit.test_web import browser, logged_in


def batches(records, broken=()):
    """Turn synthetic records into per-scope batches, failing the named datasets."""
    grouped = defaultdict(list)
    for rows in records.values():
        for row in rows:
            grouped[json.dumps(row["scope"], sort_keys=True)].append(row)
    result = []
    for key, rows in grouped.items():
        scope = Scope(**json.loads(key))
        if scope.dataset in broken:
            result.append(Batch(scope=scope, complete=False, error="Read denied"))
        else:
            result.append(
                Batch(scope=scope, records=[Record(key=r["key"], data=r["data"]) for r in rows])
            )
    return result


def coverage(store, dataset):
    return next(
        row for row in store.rows("coverage") if json.loads(row["scope"])["dataset"] == dataset
    )


def open_rules(store, scope_dataset=None):
    found = [json.loads(row["data"]) for row in store.rows("findings")]
    return {
        f["rule_id"]
        for f in found
        if f["status"] == "open"
        and (scope_dataset is None or json.loads(f["scope"])["dataset"] == scope_dataset)
    }


def test_complete_inputs_publish_findings_and_later_resolve(service, parent):
    generation = install(service.store, parent)
    service.identity_analysis(generation, parent.domain, batches(identity_records()), None)
    assert coverage(service.store, "analysis.policy")["status"] == "complete"
    assert {"POL-MANAGE-002", "POL-UNUSED-001", "IAM-GRP-001"} <= open_rules(
        service.store, "analysis.policy"
    )
    assert {"IAM-USR-001", "IAM-USR-002"} <= open_rules(service.store, "analysis.identity")
    assert open_rules(service.store, "analysis.api_keys") == {"IAM-KEY-001"}
    fixed = identity_records()
    fixed["identity.policies"] = [r for r in fixed["identity.policies"] if r["key"] != "p-stale"]
    service.identity_analysis(generation, parent.domain, batches(fixed), None)
    assert "POL-UNUSED-001" not in open_rules(service.store, "analysis.policy")
    resolved = [
        json.loads(row["data"])
        for row in service.store.rows("findings")
        if json.loads(row["data"])["rule_id"] == "POL-UNUSED-001"
    ]
    assert resolved[0]["status"] == "resolved" and resolved[0]["resolved_at"]


def test_incomplete_inputs_fail_closed_per_analysis_scope(service, parent):
    generation = install(service.store, parent)
    service.identity_analysis(generation, parent.domain, batches(identity_records()), None)
    before = open_rules(service.store, "analysis.policy")
    # Groups unreadable: policy and identity analysis must not resolve anything.
    fixed = identity_records()
    fixed["identity.policies"] = []
    service.identity_analysis(
        generation,
        parent.domain,
        batches(fixed, broken={"identity_domains.groups"}),
        None,
    )
    policy = coverage(service.store, "analysis.policy")
    assert policy["status"] == "failed" and "identity_domains.groups" in policy["error"]
    # Nothing resolved; the only addition is the explicit coverage gap for this scope.
    assert open_rules(service.store, "analysis.policy") == before | {"OGC-ACCESS-002"}
    # API keys still evaluate because their own inputs were complete.
    assert coverage(service.store, "analysis.api_keys")["status"] == "complete"


def test_denied_api_keys_block_only_key_rotation(service, parent):
    generation = install(service.store, parent)
    service.identity_analysis(
        generation,
        parent.domain,
        batches(identity_records(), broken={"identity_domains.api_keys"}),
        None,
    )
    assert coverage(service.store, "analysis.api_keys")["status"] == "failed"
    assert coverage(service.store, "analysis.policy")["status"] == "complete"
    assert "IAM-KEY-001" not in open_rules(service.store)


def test_missing_compartments_block_all_identity_analysis(service, parent):
    generation = install(service.store, parent)
    records = identity_records()
    service.identity_analysis(
        generation, parent.domain, batches(records, broken={"identity.compartments"}), None
    )
    for dataset in ("analysis.policy", "analysis.identity", "analysis.api_keys"):
        assert coverage(service.store, dataset)["status"] == "failed"
    assert open_rules(service.store) <= {"OGC-ACCESS-002"}


def publish_records(service, generation, records):
    for batch in batches(records):
        service.store.publish(generation, batch)


def complete_audit(service, generation, parent, *, backfill=True):
    region = parent.domain.home_region
    for dataset in ("audit.events", "audit.backfill"):
        scope = Scope(tenancy=parent.domain.tenancy_ocid, dataset=dataset, region=region)
        done = dataset == "audit.events" or backfill
        service.store.publish(
            generation, Batch(scope=scope, complete=done, error="" if done else "pending")
        )


def test_activity_analysis_waits_for_identity_and_audit_coverage(service, parent):
    generation = install(service.store, parent)
    service.activity_analysis(generation, parent.domain, None)
    assert "identity inventory" in coverage(service.store, "analysis.activity")["error"]
    publish_records(service, generation, identity_records())
    service.identity_analysis(generation, parent.domain, batches(identity_records()), None)
    complete_audit(service, generation, parent, backfill=False)
    service.activity_analysis(generation, parent.domain, None)
    assert "Audit coverage" in coverage(service.store, "analysis.activity")["error"]
    assert not {"IAM-USR-003", "IAM-GRP-002"} & open_rules(service.store)


def test_activity_analysis_runs_with_complete_audit_window(service, parent):
    generation = install(service.store, parent)
    publish_records(service, generation, identity_records())
    service.identity_analysis(generation, parent.domain, batches(identity_records()), None)
    complete_audit(service, generation, parent)
    tenancy = parent.domain.tenancy_ocid
    service.store.audit_commit(
        generation,
        Scope(tenancy=tenancy, dataset="audit.events", region=parent.domain.home_region),
        now().isoformat(),
        now().isoformat(),
        [{"id": "e", "time": now().isoformat(), "principal_id": "ocid1.user.oc1..u-net"}],
    )
    service.activity_analysis(generation, parent.domain, None)
    assert coverage(service.store, "analysis.activity")["status"] == "complete"
    inactive = [
        json.loads(row["data"])
        for row in service.store.rows("findings")
        if json.loads(row["data"])["rule_id"] == "IAM-USR-003"
    ]
    names = sorted(f["description"].split(":")[0] for f in inactive)
    assert "net (Default)" not in names  # Audit activity counts as use
    assert "fed (Default)" in names


def test_window_before_forward_start_counts_as_covered(service, parent):
    generation = install(service.store, parent)
    complete_audit(service, generation, parent, backfill=False)
    tenancy = parent.domain.tenancy_ocid
    since = now() - timedelta(days=90)
    assert not service.audit_window_complete(generation, tenancy, since)
    service.store.set_checkpoint(
        generation,
        Scope(tenancy=tenancy, dataset="audit.backfill.target", region=parent.domain.home_region),
        (since - timedelta(days=1)).isoformat(),
    )
    assert service.audit_window_complete(generation, tenancy, since)


def scim_user(**extra):
    return NS(
        id="u1",
        ocid="ocid1.user.oc1..u1",
        user_name="alice",
        active=True,
        password="must-not-be-kept",
        urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user=NS(mfa_status="ENROLLED"),
        urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user=NS(
            is_federated_user=False, service_user=False
        ),
        urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user=NS(
            last_successful_login_date="2026-10-20T08:00:00Z"
        ),
        **extra,
    )


def test_user_projection_keeps_mfa_federation_and_sign_in_only(monkeypatch):
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.all_items", lambda method, **k: method(**k)
    )
    captured = {}

    def list_users(**kwargs):
        captured.update(kwargs)
        return [scim_user()]

    (record,) = read_users(NS(list_users=list_users))
    assert record.data == {
        "id": "u1",
        "ocid": "ocid1.user.oc1..u1",
        "user_name": "alice",
        "active": True,
        "mfa_status": "ENROLLED",
        "federated": False,
        "service_user": False,
        "last_successful_login": "2026-10-20T08:00:00Z",
    }
    assert "mfaStatus" in captured["attributes"] and "password" not in captured["attributes"]


def test_api_key_projection_never_keeps_key_material(monkeypatch):
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.all_items", lambda method, **k: method(**k)
    )
    key = NS(
        id="k1",
        ocid="ocid1.apikey.oc1..k1",
        key="-----BEGIN PUBLIC KEY-----synthetic",
        fingerprint="aa:bb",
        user=NS(value="u1", ocid="ocid1.user.oc1..u1"),
        meta=NS(created="2026-01-01T00:00:00Z"),
    )
    (record,) = read_api_keys(NS(list_api_keys=lambda **k: [key]))
    assert record.data == {
        "id": "k1",
        "ocid": "ocid1.apikey.oc1..k1",
        "user_id": "u1",
        "user_ocid": "ocid1.user.oc1..u1",
        "created": "2026-01-01T00:00:00Z",
    }
    assert "aa:bb" not in json.dumps(record.data) and "PUBLIC KEY" not in json.dumps(record.data)


def test_api_keys_use_scim_paging():
    pages = {1: ["a", "b"], 3: ["c"]}

    def list_api_keys(**kwargs):
        start = kwargs["start_index"]
        data = NS(resources=pages[start], start_index=start, total_results=3)
        return oci.response.Response(200, {}, data, None)

    assert all_items(list_api_keys) == ["a", "b", "c"]


@pytest.fixture
def identity_client(settings, service, parent, monkeypatch):
    generation = install(service.store, parent)
    publish_records(service, generation, identity_records())
    service.identity_analysis(generation, parent.domain, batches(identity_records()), None)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    return client


def test_users_view_shows_mfa_sign_in_groups_and_keys(identity_client):
    page = identity_client.get("/identity").text
    assert "<script" not in page
    assert "Un Enrolled" in page and "Never recorded" in page
    assert "no expiry" in page and "IAM-USR-002" in page
    not_enrolled = identity_client.get("/identity?view=users&mfa=not_enrolled").text
    assert "<td>admin<small>" not in not_enrolled and "<td>net<small>" in not_enrolled
    apps = identity_client.get("/identity?view=users&domain=ocid1.domain.oc1..aaaafakeapps").text
    assert "<td>dev<small>" in apps and "<td>net<small>" not in apps


def test_groups_and_dynamic_groups_show_policy_references(identity_client):
    groups = identity_client.get("/identity?view=groups").text
    assert "NetworkAdmins" in groups and "IAM-GRP-001" in groups
    dynamic = identity_client.get("/identity?view=dynamic-groups").text
    assert "ALL {resource.type = &#39;fnfunc&#39;}" in dynamic and "IAM-DG-001" in dynamic


def test_policies_view_shows_paths_statements_and_badges(identity_client):
    page = identity_client.get("/identity?view=policies&q=network").text
    assert "network-copy" in page and "POL-DUP-001" in page and "Tenant Admin Policy" not in page
    assert "Synthetic Organization" in page


def test_analysis_view_summarizes_and_filters_rules(identity_client):
    page = identity_client.get("/identity?view=analysis").text
    assert "POL-MANAGE-002" in page and "IAM-KEY-001" in page
    critical = identity_client.get("/identity?view=analysis&severity=CRITICAL").text
    assert "Grant to manage all-resources in the tenancy" in critical
    assert "User without MFA" not in critical
    rule = identity_client.get("/identity?view=analysis&rule=IAM-USR-002").text
    assert "User without MFA" in rule and "Duplicate policy" not in rule


def test_identity_tab_rejects_unknown_views_and_values(identity_client):
    assert identity_client.get("/identity?view=secrets").status_code == 400
    assert identity_client.get("/identity?view=users&mfa=maybe").status_code == 400


def test_badges_group_repeated_rules_and_summaries_use_rule_names(identity_client):
    policies = identity_client.get("/identity?view=policies&q=iam").text
    assert "POL-XTEN-001 ×2" in policies and policies.count(">POL-XTEN-001") == 1
    analysis = identity_client.get("/identity?view=analysis").text
    assert "Grant to manage a resource type" in analysis


def test_timestamps_render_as_utc_minutes():
    from oci_governance_center.web.views import when

    assert when("2026-10-23T04:54:35.933641+00:00") == "2026-10-23 04:54 UTC"
    assert when("2026-10-20T08:00:00Z") == "2026-10-20 08:00 UTC"
    assert when("not a time") == "not a time" and when(None) == ""


def records_from_old_collector():
    """Users collected before MFA/sign-in collection, with no API-key dataset at all."""
    records = identity_records()
    for user in records["identity_domains.users"]:
        user["data"] = {k: user["data"][k] for k in ("id", "ocid", "user_name")}
    del records["identity_domains.api_keys"]
    return records


def test_uncollected_mfa_and_keys_are_unknown_not_missing(settings, service, parent, monkeypatch):
    generation = install(service.store, parent)
    records = records_from_old_collector()
    publish_records(service, generation, records)
    found = rules_by_id(service, generation, parent, records)
    assert "IAM-USR-002" not in found  # unknown MFA never becomes "user without MFA"
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    page = client.get("/identity").text
    assert "Not collected yet" in page and "Never recorded" not in page
    assert "Not Reported" not in page and "Un Enrolled" not in page
    assert page.count("Not collected</span>") == 6  # API keys: unknown for every user
    unknown = client.get("/identity?view=users&mfa=unknown").text
    assert unknown.count("Not collected yet</small>") == 6


def rules_by_id(service, generation, parent, records, broken=()):
    service.identity_analysis(generation, parent.domain, batches(records, broken), None)
    return open_rules(service.store)


def test_mfa_is_judged_only_where_oci_returned_the_attribute(service, parent):
    generation = install(service.store, parent)
    records = identity_records()
    # No user in the Default domain reports MFA: unknown, so no findings there.
    for user in records["identity_domains.users"]:
        user["data"]["mfa_status"] = None
    assert "IAM-USR-002" not in rules_by_id(service, generation, parent, records)
    # Once any user in the domain reports MFA, an unreported user counts as not enrolled.
    records["identity_domains.users"][0]["data"]["mfa_status"] = "ENROLLED"
    found = [
        json.loads(row["data"])
        for row in service.store.rows("findings")
        if json.loads(row["data"])["rule_id"] == "IAM-USR-002"
    ]
    assert found == []
    assert "IAM-USR-002" in rules_by_id(service, generation, parent, records)


def test_failed_api_key_read_shows_unknown_then_stale(settings, service, parent, monkeypatch):
    generation = install(service.store, parent)
    records = identity_records()
    for batch in batches(records, broken={"identity_domains.api_keys"}):
        service.store.publish(generation, batch)
    client = browser(settings, service)
    logged_in(client, service.store, ["ogc_viewer"])
    monkeypatch.setattr(
        "oci_governance_center.web.app.oidc.membership",
        AsyncMock(return_value=Identity(subject="human", groups=frozenset({"ogc_viewer"}))),
    )
    assert "Not collected</span>" in client.get("/identity").text
    publish_records(service, generation, records)
    for batch in batches(records, broken={"identity_domains.api_keys"}):
        if batch.scope.dataset == "identity_domains.api_keys":
            service.store.publish(generation, batch)
    stale = client.get("/identity").text
    assert "Oldest" in stale and "latest read failed" in stale


def test_user_read_logs_counts_without_identifiers(monkeypatch, caplog):
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.all_items", lambda method, **k: method(**k)
    )
    caplog.set_level("INFO", logger="oci_governance_center.collectors.inventory")
    read_users(NS(list_users=lambda **k: [scim_user()]))
    assert "total=1, mfa_status_reported=1, sign_in_reported=1" in caplog.text
    assert "alice" not in caplog.text and "u1" not in caplog.text


def test_api_key_read_sends_no_attribute_list(monkeypatch):
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.all_items", lambda method, **k: method(**k)
    )
    sent = {}

    def list_api_keys(**kwargs):
        sent.update(kwargs)
        return []

    read_api_keys(NS(list_api_keys=list_api_keys))
    assert "attributes" not in sent  # OCI rejected an explicit attribute list with HTTP 400


def test_service_errors_report_code_operation_message_and_request_id():
    from oci_governance_center.collectors.inventory import public_error

    error = oci.exceptions.ServiceError(
        400,
        "InvalidParameter",
        {"opc-request-id": "ABC123/DEF456"},
        "Invalid value for compartmentDepth\n",
        operation_name="request_summarized_usages",
    )
    message = public_error(error)
    assert "HTTP 400 InvalidParameter) in request_summarized_usages." in message
    assert "OCI says: Invalid value for compartmentDepth." in message
    assert "Request ID: ABC123/DEF456." in message
    scim = oci.exceptions.ServiceError(400, "400", {}, "attribute not supported")
    assert "HTTP 400 400" in public_error(scim)


def test_service_error_messages_are_sanitized_and_bounded():
    from oci_governance_center.collectors.inventory import public_error

    token = "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"
    hostile = oci.exceptions.ServiceError(
        400,
        "<script>",
        {"opc-request-id": "a b"},
        f"bad\x00 Authorization: Bearer {token} -----BEGIN PRIVATE KEY-----abc" + "x" * 900,
        operation_name="drop table;",
    )
    message = public_error(hostile)
    assert "<script>" not in message and "Request ID" not in message
    assert token not in message and "abc" not in message and "\x00" not in message
    assert "drop table" not in message and "Bearer [REDACTED]" in message
    assert len(message) < 500


def test_policies_view_filters_by_compartment_and_marks_unscanned_domains(identity_client, service):
    tenancy = "ocid1.tenancy.oc1..aaaafakeparent"
    attached = identity_client.get(f"/identity?view=policies&compartment={tenancy}").text
    assert "Tenant Admin Policy" in attached and "Show all compartments" in attached
    other = "ocid1.compartment.oc1..aaaafakeprod"
    assert (
        "No policies match"
        in identity_client.get(f"/identity?view=policies&compartment={other}").text
    )
    assert "not fully analyzed" not in identity_client.get("/identity?view=policies").text
    # Simulate default-domain-only collection: the Apps domain's groups were never read.
    with service.store.db() as db:
        db.execute(
            "DELETE FROM records WHERE json_extract(scope,'$.domain')=?",
            ("ocid1.domain.oc1..aaaafakeapps",),
        )
    page = identity_client.get("/identity?view=policies").text
    assert "not fully analyzed" in page and "Apps not scanned" in page
