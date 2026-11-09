import pytest
from fastapi.testclient import TestClient

from authzlab.api import create_app
from authzlab.runner import run


def test_secure_fixture_satisfies_all_policy_cases():
    report = run("secure")
    assert report["summary"] == {"total": 15, "passed": 15, "findings": 0}


def test_vulnerable_fixture_reveals_the_expected_object_access_regressions():
    report = run("vulnerable")
    failed = {row["case_id"] for row in report["results"] if not row["passed"]}
    assert failed == {"peer-read", "cross-tenant-read", "cross-tenant-admin", "peer-write", "cross-tenant-write"}
    changed = {row["case_id"] for row in report["results"] if row["unauthorized_state_change"]}
    assert changed == {"peer-write", "cross-tenant-write"}


@pytest.mark.parametrize("actor", [None, "unknown", "bob", "eve", "sam"])
def test_denied_mutations_leave_the_owners_document_unchanged(actor):
    with TestClient(create_app()) as client:
        headers = {"Authorization": f"Bearer {actor}"} if actor else {}
        denied = client.patch("/invoices/inv-100", headers=headers, json={"memo": "Attacker controlled memo"})
        assert denied.status_code in {401, 403}
        owner = client.get("/invoices/inv-100", headers={"Authorization": "Bearer alice"})
        assert owner.json()["memo"] == "Synthetic north invoice"


def test_access_policy_is_symmetric_for_the_second_tenant():
    with TestClient(create_app()) as client:
        for actor in ("eve", "sam"):
            assert client.get("/invoices/inv-200", headers={"Authorization": f"Bearer {actor}"}).status_code == 200
        for actor in ("alice", "bob", "nora"):
            assert client.get("/invoices/inv-200", headers={"Authorization": f"Bearer {actor}"}).status_code == 403


def test_client_cannot_change_owner_or_tenant_fields():
    with TestClient(create_app()) as client:
        response = client.patch("/invoices/inv-100", headers={"Authorization": "Bearer alice"}, json={"memo": "valid memo", "owner": "bob", "tenant": "south"})
        assert response.status_code == 422
        current = client.get("/invoices/inv-100", headers={"Authorization": "Bearer alice"}).json()
        assert current["owner"] == "alice" and current["tenant"] == "north"


def test_invalid_fixture_cannot_silently_run_as_secure():
    with pytest.raises(ValueError):
        create_app("typo")
