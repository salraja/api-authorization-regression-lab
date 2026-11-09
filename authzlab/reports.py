"""Portable JSON evidence, SARIF findings and JUnit results."""
import json
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree


def sarif(report: dict) -> dict:
    failures = [row for row in report["results"] if not row["passed"]]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "API Authorization Regression Lab", "version": "0.1.0", "rules": [{
                "id": "AUTHZ001", "name": "AuthorizationPolicyRegression",
                "shortDescription": {"text": "The API response violated the expected access policy"},
                "help": {"text": "Enforce tenant and ownership checks before returning or changing protected objects."},
                "properties": {"tags": ["security", "authorization", "CWE-639"]},
            }]}},
            "results": [{
                "ruleId": "AUTHZ001", "level": "error",
                "message": {"text": f"{row['title']}. Expected HTTP {row['expected_status']}, received {row['actual_status']}; response contract matches: {row['response_contract_matches']}; readback matches: {row['readback_matches']}; unauthorized state change: {row['unauthorized_state_change']}."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "authzlab/cases.py", "uriBaseId": "%SRCROOT%"}}}],
                "partialFingerprints": {"caseIdentity/v1": row["case_id"]},
                "properties": {"caseId": row["case_id"], "evidenceSha256": row["evidence_sha256"], "fixture": report["fixture"]},
            } for row in failures],
        }],
    }


def write_reports(report: dict, directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    evidence = directory / "evidence.json"
    evidence.write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    sarif_file = directory / "results.sarif"
    sarif_file.write_text(json.dumps(sarif(report), indent=2) + "\n", encoding="utf8")
    root = Element("testsuites")
    suite = SubElement(root, "testsuite", name=f"authorization-{report['fixture']}", tests=str(report["summary"]["total"]), failures=str(report["summary"]["findings"]))
    for row in report["results"]:
        case = SubElement(suite, "testcase", name=row["case_id"], classname="authorization.policy")
        if not row["passed"]:
            SubElement(case, "failure", message=row["title"]).text = f"Expected {row['expected_status']}, observed {row['actual_status']}; response contract matches={row['response_contract_matches']}; readback matches={row['readback_matches']}; unauthorized mutation={row['unauthorized_state_change']}"
    junit = directory / "junit.xml"
    ElementTree(root).write(junit, encoding="utf-8", xml_declaration=True)
    return [evidence, sarif_file, junit]
