import json
from hashlib import sha256
import subprocess
import sys
from xml.etree import ElementTree

import pytest

from authzlab.reports import write_reports
from authzlab.runner import run


def test_reports_preserve_findings_and_do_not_export_authentication_headers(tmp_path):
    report = run("vulnerable")
    evidence, sarif, junit = write_reports(report, tmp_path)
    raw = evidence.read_text(encoding="utf8")
    assert "Bearer " not in raw and '"Authorization"' not in raw
    assert "Unauthorized fixture change" not in raw  # No submitted memo/body copied.
    for row in json.loads(raw)["results"]:
        digest = row.pop("evidence_sha256")
        assert sha256(json.dumps(row, sort_keys=True).encode()).hexdigest() == digest
    results = json.loads(sarif.read_text(encoding="utf8"))["runs"][0]["results"]
    assert len(results) == 5
    assert {row["properties"]["caseId"] for row in results} == {row["case_id"] for row in report["results"] if not row["passed"]}
    suite = ElementTree.parse(junit).getroot().find("testsuite")
    assert suite.attrib["tests"] == "15" and suite.attrib["failures"] == "5"


@pytest.mark.parametrize("fixture,expected_exit,findings", [("secure", 0, 0), ("vulnerable", 1, 5)])
def test_cli_returns_a_meaningful_exit_status_and_usable_reports(tmp_path, fixture, expected_exit, findings):
    result = subprocess.run([sys.executable, "-m", "authzlab", "--fixture", fixture, "--output-dir", str(tmp_path)], text=True, capture_output=True, check=False)
    assert result.returncode == expected_exit, result.stderr
    assert f"{findings} policy violations" in result.stdout
    assert json.loads((tmp_path / "evidence.json").read_text(encoding="utf8"))["summary"]["findings"] == findings
