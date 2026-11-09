"""Compare prior cases without calling missing tests fixed."""
import json
from pathlib import Path


def load_baseline(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf8"))
    if report.get("schema_version") != "1.0" or not isinstance(report.get("results"), list):
        raise ValueError("Unsupported baseline report")
    rows = report["results"]
    if any(not isinstance(row, dict) or not isinstance(row.get("passed"), bool)
           or not isinstance(row.get("case_id"), str) or not row["case_id"]
           or not isinstance(row.get("request"), dict)
           or not isinstance(row.get("expected_status"), int)
           or not isinstance(row.get("case_contract_sha256"), str)
           or len(row["case_contract_sha256"]) != 64 for row in rows):
        raise ValueError("Baseline requires unique case identifiers, boolean results and case contracts")
    if len({row["case_id"] for row in rows}) != len(rows):
        raise ValueError("Duplicate baseline case identifiers")
    return report


def compare(previous: dict, current: dict) -> dict:
    old = {row["case_id"]: row for row in previous["results"]}
    new = {row["case_id"]: row for row in current["results"]}
    changes = []
    for case_id in sorted(old.keys() | new.keys()):
        before, after = old.get(case_id), new.get(case_id)
        if after is None:
            state = "not_run"
        elif before is None:
            state = "new" if not after["passed"] else "new_pass"
        elif before["case_contract_sha256"] != after["case_contract_sha256"]:
            state = "policy_changed"
        elif not before["passed"] and after["passed"]:
            state = "fixed"
        elif before["passed"] and not after["passed"]:
            state = "regressed"
        elif not after["passed"]:
            state = "open"
        else:
            state = "unchanged_pass"
        changes.append({"case_id": case_id, "state": state})
    states = ("new", "open", "fixed", "regressed", "not_run", "policy_changed", "new_pass", "unchanged_pass")
    return {"schema_version": "1.0", "summary": {state: sum(row["state"] == state for row in changes) for state in states}, "changes": changes}
