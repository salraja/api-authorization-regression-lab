"""Execute the policy matrix in process and record deliberately limited evidence."""
from datetime import datetime, timezone
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

from fastapi.testclient import TestClient

from .api import create_app
from .cases import load_policy


def verified_read(client: TestClient, path: str, headers: dict | None) -> dict:
    response = client.get(path, headers=headers)
    if response.status_code != 200:
        raise ValueError("State verification identity must be able to read the protected object")
    return response.json()


def run(mode: str = "secure", policy_path: Path | None = None) -> dict:
    policy, cases = load_policy(policy_path)
    results = []
    for case in cases:
        # Independent state for every case prevents one failed write hiding another.
        with TestClient(create_app(mode)) as client:
            headers = {"Authorization": f"Bearer {case.actor}"} if case.actor else {}
            verification_headers = {"Authorization": f"Bearer {case.verify_actor}"} if case.verify_actor else None
            before = verified_read(client, case.path, verification_headers) if case.expect_unchanged else None
            response = client.request(case.method, case.path, headers=headers, json=case.body)
            data = response.json()
            # Evidence is an allowlist, never a copy of request headers or arbitrary bodies.
            evidence = {key: data[key] for key in ("id", "tenant", "owner") if key in data}
            state_changed = False
            if case.expect_unchanged:
                state_changed = verified_read(client, case.path, verification_headers) != before
            status_matches = response.status_code == case.expected
            contract_matches = all(data.get(key) == value for key, value in (case.expected_response or {}).items())
            readback_matches = True
            if case.method == "PATCH" and case.expected == 200 and verification_headers:
                observed = verified_read(client, case.path, verification_headers)
                readback_matches = all(observed.get(key) == value for key, value in (case.expected_response or {}).items())
            passed = status_matches and contract_matches and readback_matches and not state_changed
            result = {
                "case_id": case.id, "title": case.title,
                "request": {"method": case.method, "path": case.path, "actor": case.actor or "anonymous"},
                "expected_status": case.expected, "actual_status": response.status_code,
                "passed": passed, "unauthorized_state_change": state_changed,
                "response_contract_matches": contract_matches, "readback_matches": readback_matches,
                "case_contract_sha256": sha256(json.dumps(asdict(case), sort_keys=True).encode()).hexdigest(),
                "response_evidence": evidence,
            }
            result["evidence_sha256"] = sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
            results.append(result)
    findings = sum(not item["passed"] for item in results)
    return {
        "schema_version": "1.0", "fixture": mode,
        "policy": policy,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Synthetic local FastAPI fixtures only; no external HTTP requests",
        "summary": {"total": len(results), "passed": len(results) - findings, "findings": findings},
        "results": results,
    }
