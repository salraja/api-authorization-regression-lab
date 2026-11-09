# Design and security assumptions

## Protected assets and trust boundaries

The protected asset is an invoice belonging to one owner and one tenant. The client controls the path, request body and claimed fixture identity. The API must make the authorization decision using the server's invoice record and principal registry. An administrator's authority ends at their own tenant.

The local fixture does not implement production authentication. Public identity names stand in for an already authenticated principal so the exercises can focus on authorization. A deployed service would need verified tokens, secure key handling and a separate review of authentication and session behavior.

## Policy oracle

The JSON policy describes expected behavior independently of the authorization function. Positive cases prevent a blanket deny implementation from looking correct. Response contract checks catch a successful status that returns the wrong object. Readback checks catch ignored writes. Denied changes are checked against the complete object before and after the request, using a principal known to have read access.

Every case gets a fresh application and data store. An unauthorized write cannot change the starting state for the next test or erase the evidence of another failure.

| Abuse case | Example check | Intended control |
| --- | --- | --- |
| Read another owner's object | `peer-read` | Object ownership or tenant administrator permission |
| Read across tenants | `cross-tenant-read` | Server side tenant boundary |
| Use administrator rights in another tenant | `cross-tenant-admin` | Tenant scoped administrator permission |
| Modify another user's data | `peer-write`, `cross-tenant-write` | Authorization before mutation and readback verification |
| Rewrite ownership through an allowed update | `tenant-field-injection` | Explicit update model and rejection of extra properties |
| Weaken a test and call it fixed | Baseline case contract comparison | A policy change is distinct from a verified fix |

## Evidence design

Reports do not store authorization headers or submitted request bodies. Response evidence includes only object identifier, tenant and owner from this synthetic fixture. Case contract digests include the complete policy case, while evidence digests include each exported result. A digest can identify a change if a trusted prior value is available; an attacker who controls a file can recompute it. Reports are not signed.

SARIF findings point to the local policy case file. They do not pretend to identify a source line in an external application. JUnit reports include every policy check, including successful checks.

## Baselines and CI

A finding is fixed only when the same case contract passes on a later run. A previously passing case that now fails is a regression. Missing tests are reported as not run, and new cases remain distinguishable. A changed request, expected response, verifier or expected status changes the case contract and cannot silently count as remediation.

The CI workflow verifies both fixtures. Merely running a vulnerable example and getting a successful workflow would be misleading, so the workflow explicitly expects the vulnerable runner to return exit code 1. Evidence is saved for inspection.

## Deliberate limits

The fixture uses in memory state and does not model concurrent updates, database isolation, real tokens, token expiry or infrastructure access controls. The access policy returns 403 for existing but forbidden invoices and 404 for missing invoices; that distinction can reveal object existence and is not an enumeration resistance demonstration. Production tests would need an agreed response policy and approved test environment.
