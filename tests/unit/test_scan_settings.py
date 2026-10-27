"""Per-tenancy scan settings: storage, Scan tab controls and collection gating."""

import json
from types import SimpleNamespace as NS

import pytest

from oci_governance_center.collectors.inventory import Trace, inventory
from oci_governance_center.models import Batch, Record, ScanSettings, Scope
from tests.conftest import install
from tests.unit.test_scans import signed_in

APPS = "ocid1.domain.oc1..aaaafakeapps"


@pytest.fixture
def sdk(domain, monkeypatch):
    """Synthetic SDK clients for every family; records which domain endpoints were read."""
    read_domains: list[str] = []

    def domain_record(ident, name, kind, guid):
        return NS(
            id=ident,
            compartment_id=domain.tenancy_ocid,
            display_name=name,
            url=f"https://idcs-{guid * 32}.identity.oraclecloud.com",
            home_region="us-ashburn-1",
            type=kind,
            lifecycle_state="ACTIVE",
        )

    def domains_client(endpoint):
        def users(**_):
            read_domains.append(endpoint)
            return []

        return NS(
            list_users=users,
            list_groups=lambda **_: [],
            list_dynamic_resource_groups=lambda **_: [],
            list_api_keys=lambda **_: [],
        )

    clients = {
        "identity": NS(
            list_compartments=lambda *a, **k: [],
            list_region_subscriptions=lambda *_: [],
            list_policies=lambda *_: [],
            list_domains=lambda *_: [
                domain_record(domain.domain_ocid, "Default", "DEFAULT", "a"),
                domain_record(APPS, "Apps", "SECONDARY", "b"),
            ],
        ),
        "guard": NS(
            get_configuration=lambda *_: NS(data=NS(status="ENABLED", reporting_region=None)),
            list_problems=lambda *a, **k: [],
            list_security_zones=lambda *a, **k: [],
        ),
        "optimizer": NS(
            list_enrollment_statuses=lambda *_: [],
            list_categories=lambda *_: [],
            list_recommendations=lambda *_: [],
        ),
    }

    def client(kind, signer, region, endpoint=None):
        return domains_client(endpoint) if kind == "domains" else clients[kind]

    monkeypatch.setattr("oci_governance_center.collectors.inventory.client", client)
    monkeypatch.setattr(
        "oci_governance_center.collectors.inventory.all_items",
        lambda method, *a, **k: method(*a, **k),
    )
    return read_domains


def collect(domain, settings):
    return {b.scope.dataset for b in inventory(object(), domain, "all", settings)}


def test_default_settings_read_only_the_default_domain(domain, sdk):
    datasets = collect(domain, ScanSettings())
    assert len(sdk) == 1 and "idcs-aaaa" in sdk[0]
    assert {"identity_domains.users", "identity.policies", "cloud_guard.configuration"} <= datasets
    assert "optimizer.recommendations" in datasets


def test_all_domains_reads_every_active_domain(domain, sdk):
    collect(domain, ScanSettings(all_domains=True))
    assert len(sdk) == 2


@pytest.mark.parametrize(
    "flag,absent,present",
    [
        ("identities", "identity_domains.", "identity.policies"),
        ("policies", "identity.policies", "identity_domains.users"),
        ("cloud_guard", "cloud_guard.", "optimizer.recommendations"),
        ("cloud_advisor", "optimizer.", "cloud_guard.configuration"),
    ],
)
def test_disabled_datasets_yield_no_batch(domain, sdk, flag, absent, present):
    datasets = collect(domain, ScanSettings(**{flag: False}))
    assert not any(d.startswith(absent) for d in datasets)
    assert present in datasets
    # Prerequisites are always collected.
    assert {"identity.compartments", "identity.domains", "identity.regions"} <= datasets


def test_settings_default_save_and_clear_on_replacement(store, parent):
    generation = install(store, parent)
    tenancy = parent.domain.tenancy_ocid
    assert store.scan_settings(tenancy) == ScanSettings()
    chosen = ScanSettings(cloud_advisor=False, all_domains=True)
    store.save_scan_settings(generation, tenancy, chosen, "admin")
    assert store.scan_settings(tenancy) == chosen
    actions = [row["action"] for row in store.rows("control_events")]
    assert "scan_settings_changed" in actions
    install(store, parent)
    assert store.scan_settings(tenancy) == ScanSettings()


def test_admin_saves_settings_from_the_scan_tab(settings, service, parent, monkeypatch):
    client = signed_in(settings, service, parent, monkeypatch, "ogc_admin")
    tenancy = parent.domain.tenancy_ocid
    page = client.get("/scans").text
    assert "What to collect" in page and "Default domain only" in page and "<script" not in page
    response = client.post(
        f"/scans/settings/{tenancy}",
        data={"csrf": "synthetic-csrf", "cloud_guard": "on", "policies": "on", "domains": "all"},
    )
    assert response.status_code == 303
    assert service.store.scan_settings(tenancy) == ScanSettings(
        cloud_advisor=False, identities=False, audit=False, all_domains=True, cost=False
    )
    assert client.post(f"/scans/settings/{tenancy}", data={}).status_code == 403
    unknown = client.post(
        "/scans/settings/ocid1.tenancy.oc1..other", data={"csrf": "synthetic-csrf"}
    )
    assert unknown.status_code == 404


def test_viewer_sees_settings_but_cannot_change_them(settings, service, parent, monkeypatch):
    client = signed_in(settings, service, parent, monkeypatch, "ogc_viewer")
    page = client.get("/scans").text
    assert "What to collect" in page and "disabled" in page
    tenancy = parent.domain.tenancy_ocid
    response = client.post(f"/scans/settings/{tenancy}", data={"csrf": "synthetic-csrf"})
    assert response.status_code == 403


def analysis_batches(tenancy, domain_ocid):
    def batch(dataset, records, domain=""):
        scope = Scope(tenancy=tenancy, dataset=dataset, region="us-ashburn-1", domain=domain)
        return Batch(scope=scope, records=records)

    statement = "Allow group Ghosts to manage all-resources in tenancy"
    return [
        batch("identity.compartments", []),
        batch(
            "identity.domains",
            [Record(key=domain_ocid, data={"id": domain_ocid, "display_name": "Default"})],
        ),
        batch(
            "identity.policies",
            [
                Record(
                    key="p",
                    data={
                        "id": "p",
                        "name": "p",
                        "compartment_id": tenancy,
                        "statements": [statement],
                    },
                )
            ],
        ),
    ]


def coverage(store):
    return {row["scope"]: row["status"] for row in store.rows("coverage")}


def test_analysis_follows_settings_without_coverage_gaps(service, parent):
    generation = install(service.store, parent)
    domain = parent.domain
    batches = analysis_batches(domain.tenancy_ocid, domain.domain_ocid)
    service.identity_analysis(
        generation, domain, batches, None, None, ScanSettings(identities=False)
    )
    scopes = coverage(service.store)
    assert any('"analysis.policy"' in s and v == "complete" for s, v in scopes.items())
    assert not any('"analysis.identity"' in s or '"analysis.api_keys"' in s for s in scopes)
    rules = {json.loads(r["data"])["rule_id"] for r in service.store.rows("findings")}
    # Groups were not read, so the unresolved group is unknown, never stale or unused.
    assert "POL-MANAGE-002" in rules
    assert not {"POL-STALE-001", "POL-UNUSED-001"} & rules
    assert not any(v == "failed" for v in scopes.values())


def test_policy_analysis_disabled_publishes_nothing(service, parent):
    generation = install(service.store, parent)
    domain = parent.domain
    batches = analysis_batches(domain.tenancy_ocid, domain.domain_ocid)[:2]
    service.identity_analysis(
        generation, domain, batches, None, None, ScanSettings(policies=False, identities=False)
    )
    assert not any("analysis." in scope for scope in coverage(service.store))


def test_scan_trace_names_tenancy_and_each_phase(domain, sdk, caplog):
    caplog.set_level("INFO", logger="oci_governance_center.collectors.inventory")
    trace = Trace("ktdemos-synthetic")
    for batch in inventory(object(), domain, "all", ScanSettings(), trace):
        trace.seen(batch)
    trace.finish()
    messages = [r.getMessage() for r in caplog.records if r.getMessage().startswith("tenancy:")]
    phases = ["Compartment", "IAM policy", "Identity", "Cloud Guard", "Cloud Advisor"]
    expected = []
    for phase in phases:
        expected += [
            f"tenancy: ktdemos-synthetic {phase} scan started",
            f"tenancy: ktdemos-synthetic {phase} scan completed",
        ]
    assert messages == expected


def test_scan_trace_reports_gaps_and_failures(caplog):
    caplog.set_level("INFO", logger="oci_governance_center.collectors.inventory")
    trace = Trace("child")
    trace.start("Cloud Guard")
    scope = Scope(tenancy="t", dataset="cloud_guard.problems", region="r")
    trace.seen(Batch(scope=scope, complete=False, error="denied"))
    trace.start("Cloud Advisor")
    trace.fail()
    trace.finish()  # nothing left open after a failure
    messages = [r.getMessage() for r in caplog.records]
    assert (
        "tenancy: child Cloud Guard scan completed with 1 incomplete scope (see Coverage)"
        in messages
    )
    assert messages[-1] == "tenancy: child Cloud Advisor scan failed"
    assert "tenancy: child Cloud Guard scan: cloud_guard.problems incomplete: denied" in messages
