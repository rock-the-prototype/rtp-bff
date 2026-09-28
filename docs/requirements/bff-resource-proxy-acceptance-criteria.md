# BFF Controlled Resource Proxy Acceptance Criteria

- **Status:** Proposed
- **Date:** 2026-09-28
- **Decision:** ADR-0006

| ID | Requirement | Scenario | Expected observation |
|---|---|---|---|
| AC-BFF-PROXY-001 | REQ-001 | Unknown proxy route | Rejected; zero upstream requests |
| AC-BFF-PROXY-002 | REQ-002/004 | Absolute URL supplied by browser | Cannot alter destination; supplied host receives zero requests |
| AC-BFF-PROXY-003 | REQ-003 | Destination-like session data | Cannot influence route resolution |
| AC-BFF-PROXY-004 | REQ-004/007 | Resolve `projects.read` | Approved logical service selected |
| AC-BFF-PROXY-005 | REQ-005 | Production route uses HTTP | Policy rejected |
| AC-BFF-PROXY-006 | REQ-006 | Invalid/untrusted upstream certificate | TLS fails closed; no application request succeeds |
| AC-BFF-PROXY-007 | REQ-006 | Hostname mismatch | TLS fails closed |
| AC-BFF-PROXY-008 | REQ-008/027 | GET/HEAD approved route | May proceed after all checks |
| AC-BFF-PROXY-009 | REQ-008/027 | POST/PUT/PATCH/DELETE | Rejected before token resolution/upstream contact |
| AC-BFF-PROXY-010 | REQ-009/011 | Traversal/encoded separator/scheme-like value | Rejected before upstream contact |
| AC-BFF-PROXY-011 | REQ-010 | Unlisted query parameter | Not implicitly forwarded |
| AC-BFF-PROXY-012 | REQ-012 | Invalid route plus valid session | Token resolver is not invoked for unauthorized destination |
| AC-BFF-PROXY-013 | REQ-013/015 | Active session and valid AT | Approved upstream gets exactly one server-side Bearer header |
| AC-BFF-PROXY-014 | REQ-013 | Expiring AT | Existing refresh lifecycle resolves usable token |
| AC-BFF-PROXY-015 | REQ-013 | Missing/stale session | Zero upstream requests |
| AC-BFF-PROXY-016 | REQ-013 | Temporarily unavailable token resolution | Fails closed; zero upstream requests |
| AC-BFF-PROXY-017 | REQ-014/015 | Browser supplies attacker Authorization | Browser token never reaches upstream |
| AC-BFF-PROXY-018 | REQ-016 | Browser carries BFF session cookie | Resource Server receives no BFF cookie |
| AC-BFF-PROXY-019 | REQ-017 | Sensitive/hop-by-hop headers supplied | Prohibited values absent or BFF-controlled |
| AC-BFF-PROXY-020 | REQ-018 | Upstream redirects to arbitrary host | Redirect not followed; target gets zero requests |
| AC-BFF-PROXY-021 | REQ-019 | Upstream sends Set-Cookie | Browser response omits it |
| AC-BFF-PROXY-022 | REQ-020 | Inspect response/log/error | No OAuth/session/client secrets |
| AC-BFF-PROXY-023 | REQ-021 | Invalid/duplicate/ambiguous policy | Snapshot rejected |
| AC-BFF-PROXY-024 | REQ-022 | Replace policy during requests | Request sees complete old or new snapshot |
| AC-BFF-PROXY-025 | REQ-023 | Invalid replacement | Last valid snapshot remains or proxy becomes unavailable |
| AC-BFF-PROXY-026 | REQ-024 | Browser/user attempts policy mutation | No such capability is exposed |
| AC-BFF-PROXY-027 | REQ-025 | Activate policy | Non-secret version/digest available |
| AC-BFF-PROXY-028 | REQ-026 | Resource Server rejects token/scope | Resource Server decision remains authoritative |
| AC-BFF-PROXY-029 | REQ-002/004/011/015 | Destination manipulation exfiltration attempt | Access token reaches no non-approved host |
