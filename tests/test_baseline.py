from copy import deepcopy
import json
from pathlib import Path

import pytest

from authzlab.baseline import compare, load_baseline
from authzlab.cases import load_policy
from authzlab.runner import run


def test_secure_retest_reports_five_fixes_and_reverse_reports_five_regressions():
    secure, vulnerable = run("secure"), run("vulnerable")
    assert compare(vulnerable, secure)["summary"]["fixed"] == 5
    assert compare(secure, vulnerable)["summary"]["regressed"] == 5
    assert compare(vulnerable, vulnerable)["summary"]["open"] == 5


def test_unexecuted_case_is_not_marked_fixed_and_new_failure_is_distinct():
    previous = run("vulnerable")
    current = deepcopy(previous)
    missing = current["results"].pop(0)["case_id"]
    extra = deepcopy(current["results"][0])
    extra.update(case_id="added-failing-case", passed=False)
    current["results"].append(extra)
    states = {row["case_id"]: row["state"] for row in compare(previous, current)["changes"]}
    assert states[missing] == "not_run"
    assert states["added-failing-case"] == "new"


def test_weakened_case_expectations_are_not_reported_as_a_fix():
    previous = run("vulnerable")
    current = deepcopy(previous)
    row = next(row for row in current["results"] if not row["passed"])
    row.update(passed=True, expected_status=200, case_contract_sha256="a" * 64)
    states = {item["case_id"]: item["state"] for item in compare(previous, current)["changes"]}
    assert states[row["case_id"]] == "policy_changed"


@pytest.mark.parametrize("bad", [{"schema_version": "2.0", "results": []}, {"schema_version": "1.0", "results": [{"case_id": "x", "passed": "false"}]}])
def test_malformed_baseline_is_rejected(tmp_path, bad):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        load_baseline(path)


def test_duplicate_case_ids_and_external_urls_are_rejected(tmp_path):
    policy = json.loads(Path("authzlab/policy.json").read_text())
    path = tmp_path / "policy.json"
    policy["cases"].append(policy["cases"][0])
    path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="unique"):
        load_policy(path)
    policy["cases"].pop()
    policy["cases"][0]["path"] = "https://example.org/not-a-target"
    path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="local"):
        load_policy(path)


def test_wrong_verification_identity_cannot_hide_a_mutation(tmp_path):
    policy = json.loads(Path("authzlab/policy.json").read_text())
    case = next(row for row in policy["cases"] if row["id"] == "peer-write")
    case["verify_actor"] = "bob"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="verification identity"):
        run("secure", path)


@pytest.mark.parametrize("case_id,field,wrong_value", [("owner-read", "id", "inv-999"), ("owner-write", "memo", "A write that never happened")])
def test_success_status_alone_does_not_satisfy_the_response_contract(tmp_path, case_id, field, wrong_value):
    policy = json.loads(Path("authzlab/policy.json").read_text())
    case = next(row for row in policy["cases"] if row["id"] == case_id)
    case["expected_response"][field] = wrong_value
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy))
    report = run("secure", path)
    result = next(row for row in report["results"] if row["case_id"] == case_id)
    assert result["actual_status"] == 200
    assert result["response_contract_matches"] is False and result["passed"] is False
    if case_id == "owner-write":
        assert result["readback_matches"] is False
