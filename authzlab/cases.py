"""Versioned expected access policy, separate from the API implementation."""
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    method: str
    path: str
    actor: str | None
    expected: int
    body: dict | None = None
    expected_response: dict | None = None
    verify_actor: str | None = None
    expect_unchanged: bool = False


def load_policy(path: Path | None = None) -> tuple[dict, tuple[Case, ...]]:
    data = json.loads((path or Path(__file__).with_name("policy.json")).read_text(encoding="utf8"))
    if data.get("schema_version") != "1.0" or not data.get("policy_version"):
        raise ValueError("Policy requires schema_version 1.0 and policy_version")
    cases = tuple(Case(**row) for row in data["cases"])
    if not cases or len({case.id for case in cases}) != len(cases):
        raise ValueError("Policy case identifiers must be nonempty and unique")
    for case in cases:
        if not case.id or case.method not in {"GET", "PATCH"}:
            raise ValueError("Policy requires case identifiers and GET/PATCH methods")
        if not case.path.startswith("/") or case.path.startswith("//") or "://" in case.path:
            raise ValueError("Policy paths must be local relative API paths")
        if not 100 <= case.expected <= 599:
            raise ValueError("Expected status must be an HTTP status code")
        if case.expect_unchanged and not case.verify_actor:
            raise ValueError("State verification requires a verification identity")
    metadata = {key: data[key] for key in ("schema_version", "policy_name", "policy_version")}
    metadata["sha256"] = sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    return metadata, cases


POLICY, CASES = load_policy()
