# API Authorization Regression Lab

A portfolio engineering project for testing object ownership, tenant boundaries and administrator permissions in a small API. The lab separates the access policy from the application, runs the same checks against secure and intentionally vulnerable fixtures, and saves evidence that can be reviewed in CI.

This is a local demonstration using synthetic invoices and identities. It has no company targets, customer data or external scanning feature. The fixture identities are public test inputs, not real service credentials.

## What it does

The FastAPI fixture exposes a public catalog and protected invoice read and update routes. A versioned JSON policy defines 15 checks. They cover anonymous requests, invalid identities, object owners, other members of the same tenant, tenant administrators, users from other tenants, missing objects and attempts to change protected fields.

The runner checks status codes and response contracts. It reads objects again after denied changes to verify that the data stayed unchanged, and after permitted changes to verify that the update actually took effect. Each case starts with an independent data store.

Reports include an evidence JSON file, SARIF findings and JUnit results. Evidence excludes authentication headers and request bodies. It keeps only an allowlist of response fields and attaches SHA 256 hashes to individual result records. Those hashes help detect accidental changes; they are not signatures or proof against a malicious editor.

An optional baseline comparison distinguishes new, open, fixed and regressed findings. Missing tests are marked `not_run`. Changes to a case's request or expected behavior are marked `policy_changed`, so weakening a test does not count as a fix.

## Quick start

Python 3.11 or newer is required. The project was tested with Python 3.12 on Windows. The GitHub workflow uses Python 3.12 on Ubuntu.

```console
python -m venv .venv
```

Activate the environment using the command for your shell.

```powershell
.\.venv\Scripts\Activate.ps1
```

```bash
source .venv/bin/activate
```

Install the tested dependencies and the local package, then run the tests.

```console
python -m pip install -r requirements.lock
python -m pip install -e . --no-deps
python -m pytest
python -m authzlab --fixture secure --output-dir artifacts/secure
```

The secure fixture should report:

```text
secure: 15/15 checks passed, 0 policy violations
```

Run the intentionally vulnerable fixture to see the negative control.

```console
python -m authzlab --fixture vulnerable --output-dir artifacts/vulnerable
```

It should report:

```text
vulnerable: 10/15 checks passed, 5 policy violations
```

That command intentionally returns exit code 1. The five failures are unauthorized reads by a peer, another tenant's member and another tenant's administrator, plus unauthorized writes by a peer and another tenant's member. The write checks also demonstrate that the unauthorized requests changed stored data.

## Retest and compare

After generating the vulnerable report, retest the secure fixture against it.

```console
python -m authzlab --fixture secure --baseline artifacts/vulnerable/evidence.json --output-dir artifacts/retest
```

`artifacts/retest/comparison.json` should show five fixed findings. Reverse the fixtures to demonstrate five regressions.

```console
python -m authzlab --fixture vulnerable --baseline artifacts/secure/evidence.json --output-dir artifacts/regression
```

The exit code reflects the current findings, not the number of fixes or differences. Code 0 means the current policy checks passed. Code 1 means a policy violation was found. Invalid input returns code 2.

## Policy and reports

The policy lives in `authzlab/policy.json`. It records its own schema and policy versions. Each evidence report includes a policy digest and a digest for the individual case contract. The API enforces its policy in `authzlab/api.py`; expected access behavior is recorded separately in the JSON file.

To try a policy variation, copy the file, change its version and cases, and provide it explicitly.

```console
python -m authzlab --policy path/to/policy.json --fixture secure --output-dir artifacts/custom
```

Policy paths must be relative API paths. Requests are sent through an in process ASGI test client. There is no option to supply an external host or URL.

| File | Purpose |
| --- | --- |
| `evidence.json` | Expected and observed outcomes, limited evidence, case and evidence digests |
| `results.sarif` | Failed policy checks for tools that read SARIF 2.1.0 |
| `junit.xml` | All check results for CI test reports |
| `comparison.json` | Changes from a supplied baseline |

The `examples` directory contains actual generated secure, vulnerable and retest reports. They use only the public fixture data.

## CI

The GitHub Actions workflow installs the pinned dependencies, runs the Python tests, verifies that the secure fixture passes and verifies that the vulnerable fixture returns code 1. It saves the evidence files as an artifact. The workflow has read access to repository contents and does not need secrets.

The tests cover policy outcomes, denied write integrity, a second tenant, protected field validation, report consistency, evidence digests, baseline state transitions, malformed inputs and command exit codes.

## Optional API inspection

The default web application always uses the secure fixture. To inspect the API locally:

```console
python -m uvicorn authzlab.api:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`. Fixture identities are `alice`, `bob`, `nora`, `eve` and `sam`. Enter one identity as the bearer token in the documentation's Authorize dialog. `nora` is the administrator for tenant `north`; `sam` is the administrator for `south`.

## Scope and limitations

This project demonstrates an authorization regression approach. It is not a complete security scanner, authentication service or production deployment. The synthetic fixture uses simple identities instead of verifying signed tokens. It tests a deliberately small set of routes and policy decisions. It does not test every HTTP method, token expiry, race condition, enumeration behavior or deployment configuration. A real integration would need an agreed access policy, representative test data and an authorized environment.

The intentionally vulnerable mode exists only for local regression exercises. The project does not claim that its fixture findings are vulnerabilities in any employer's systems.
