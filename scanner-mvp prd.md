

PRD
Product Requirements Document
Distributed Vulnerability Assessment Platform – MVP v1.1 (Updated)
1. Purpose
Build a simple distributed vulnerability assessment MVP that can run external and internal scans, store findings, and generate basic PCI-oriented reports. This MVP must follow the provided flow exactly and must avoid production-grade additions or extra compliance workflows not explicitly included in the current scope.

Update (v1.1): Both scan types (internal and external) must now execute both scanning engines — Nuclei and OpenVAS — in parallel, rather than one engine per scan type. This is a confirmed scope change from the client and supersedes the earlier single-engine-per-scan-type model.

2. Product goal
The product should provide immediate operational value by allowing a user to:

Add assets.

Trigger internal or external scans.

Route scans through the correct scan path.

Run both Nuclei and OpenVAS in parallel for every scan, regardless of scan type.

Collect vulnerability findings from both engines independently.

View per-engine scan status and progress.

Generate reports in PDF and CSV.

3. Scope principles
This MVP must stay simple and in-scope:

No login/authentication in v1.

No RBAC in v1.

No dispute workflow.

No attestation/signature workflow.

No SIEM or ticketing integrations.

No AI prioritization.

No multi-tenancy.

No advanced production orchestration beyond what is needed to support the shown scan flow.

No merging or tagging of findings between engines — Nuclei and OpenVAS results must remain structurally separate at all times.

No single blanket pass/fail scan status — engine-level outcomes must be independently trackable.

If any requirement is not present in the shared flow or current MVP scope, it should be treated as out of scope for this PRD.

Users
4. Primary users
This MVP serves these user roles at a functional level:

Security administrator, to add assets, deploy agents, and start scans.

Security analyst, to review findings from each engine.

Executive user, to view report summaries.

For v1, these roles do not require permission separation in the product because authentication and RBAC are intentionally excluded.

Product flow
5. Core workflow
The system must follow this exact flow:

User accesses the Flask application.

User creates or selects a scan.

User chooses scan type: external or internal.

Regardless of scan type chosen, the scan manager triggers both Nuclei and OpenVAS as independent parallel executions against the selected target(s).

If external, both engines execute against internet-facing targets via the external scan path.

If internal, both engines execute against internal targets via the internal scan path (through the presence agent where applicable).

Each engine runs independently — one engine's failure or delay must not block, interrupt, or invalidate the other engine's execution.

Findings are returned to the control plane per engine.

Findings are stored and shown in the dashboard, kept structurally separate by engine (no merging, no combined list).

Reports are generated from stored scan data, reflecting both engines' results separately.

6. Scan paths
6.1 External scan path
Triggered from Flask scan manager.

Executes both external OpenVAS and Nuclei in parallel.

Intended for internet-facing assets.

Each engine's execution, status, and findings are tracked independently within the same scan record.

6.2 Internal scan path
Triggered from Flask scan manager.

Routed to internal network.

Requires presence agent (for OpenVAS internal execution path).

Executes both internal OpenVAS and Nuclei in parallel against internal assets such as servers and endpoints.

Each engine's execution, status, and findings are tracked independently within the same scan record.

Features
7. Included features
7.1 Flask control plane
The control plane must be an AWS-hosted Flask application responsible for:

Dashboard.

Asset inventory.

Scan creation.

Scan scheduling.

Dual-engine scan orchestration (launching Nuclei and OpenVAS in parallel per scan).

Report generation.

Agent management.

7.2 Dashboard
The dashboard should show:

Total assets.

Scan list.

Overall scan status, computed from combined per-engine states (see Section 7.4 for status logic).

Recent findings summary, shown separately per engine.

Reports list.

Agent presence status.

This should be simple and operational, not an advanced analytics dashboard.

7.3 Asset inventory
The system must allow adding and storing asset records. The minimum asset data model comes from the provided schema:

Asset ID.

Hostname.

IP Address.

Environment.

Criticality.

7.4 Scan management
The system must allow:

Creating a new scan.

Choosing scan type: internal or external.

Selecting target assets.

Viewing overall scan status and per-engine scan status independently.

Scheduling scans.

The minimum scan data model must include:

Scan ID.

Type (internal/external).

Overall Status.

Start Time.

End Time.

Engine sub-records (one for Nuclei, one for OpenVAS), each with:

Engine Status (Queued, Running, Completed, Failed).

Engine Start Time.

Engine End Time.

Engine Progress.

Failure Reason (if failed).

Overall scan status logic:

Running — one or both engines are still in progress.

Partially Completed — one engine has finished (completed or failed) while the other is still running.

Completed — both engines have finished, regardless of individual engine outcome; each engine's own result (success or failure) remains visible in its own section.

A scan must never show a single misleading "Failed" or "Completed" status that hides the true per-engine outcome. If one engine succeeds and the other fails, the scan reflects both outcomes transparently.

7.5 Agent management
The MVP must support:

Internal presence agent visibility.

External scanner agent presence as operational infrastructure.

Basic agent status display in dashboard.

For v1, agent management should remain minimal and focused on whether the internal path is available for both engines.

7.6 Internal scanning capability
Internal scanning must support both engines running in parallel:

Nuclei (internal):

Template-based vulnerability and misconfiguration checks against internal targets.

OpenVAS/Greenbone (internal):

Host discovery.

Port scanning.

Service enumeration.

Vulnerability scanning.

Technologies listed for internal agent:

Nmap (supporting discovery, used by OpenVAS path).

OpenVAS / Greenbone.

Nuclei.

Python plugins.

Docker.

Linux VM.

7.7 External scanning capability
External scanning must support both engines running in parallel:

Nuclei (external):

Template-based vulnerability, misconfiguration, and exposure checks against internet-facing targets.

OpenVAS (external):

Internet-facing vulnerability assessment.

TLS assessment.

DNS assessment.

Exposure monitoring.

Both external OpenVAS and Nuclei execute in the external path as independent parallel jobs against the same target(s).

7.8 Findings management
The system must store and display findings separately per engine. The minimum findings schema is:

Asset.

Severity.

CVE (where applicable — Nuclei findings may not always have a CVE).

Description.

Recommendation.

Engine reference (internal data field only, used to structurally separate display sections — not shown as a UI tag on individual findings).

Findings from Nuclei and OpenVAS must be displayed in distinct sections/blocks in the UI (e.g., "Nuclei Results" and "OpenVAS Results") and must never be merged into a single combined findings list.

7.9 Reporting
The MVP must generate these reports:

Executive Summary.

Technical Findings (shown as separate subsections for Nuclei findings and OpenVAS findings).

Asset Inventory.

PCI-Oriented Assessment Report.

Supported formats:

PDF.

CSV.

Scan coverage
8. Minimum scan checks
The MVP should implement the checks listed in the provided scope and tool requirements, distributed across both engines as applicable to their capabilities.

8.1 Network discovery
Live host detection.

Open TCP ports.

Open UDP ports.

Service identification.

OS fingerprinting.

Primary tool: Nmap (supporting OpenVAS discovery phase).

8.2 Service exposure checks
Detect exposed: FTP, Telnet, SSH, SMTP, DNS, SNMP, SMB, RDP, HTTP, HTTPS.

8.3 TLS / SSL assessment
Detect: SSLv2 enabled, SSLv3 enabled, weak TLS configurations, expired certificates, self-signed certificates, weak ciphers, anonymous ciphers, RC4 support, 3DES support, certificate hostname mismatch.

8.4 Web server security checks
Detect: missing HSTS, missing CSP, missing X-Frame-Options, missing X-Content-Type-Options, server version disclosure, directory listing exposure, default pages, weak cookie flags.

8.5 Authentication exposure checks
Detect: default credentials, anonymous access, guest access, weak administrative interfaces.

8.6 Remote administration exposure
Detect: public RDP, public SSH, public management portals, public hypervisor interfaces.

8.7 DNS security checks
Detect: zone transfer exposure, open recursion, information disclosure.

8.8 SMB security checks
Detect: SMBv1 enabled, null sessions, signing disabled, known SMB vulnerabilities.

8.9 Database exposure checks
Detect: public databases, default configurations, version disclosure.

Supported databases: MySQL, PostgreSQL, MSSQL, MongoDB.

8.10 Vulnerability intelligence
OpenVAS findings must provide: CVE mapping, CVSS scores, severity ratings.

Nuclei findings must provide: template ID/name, severity classification, matched evidence.

Severity levels (both engines): Critical, High, Medium, Low, Informational.

Architecture
9. System architecture
9.1 Control plane
The control plane runs on AWS and includes:

Flask.

PostgreSQL.

Redis.

S3.

Responsibilities:

Scan orchestration, including launching and tracking two parallel engine executions per scan.

Reporting.

Scheduling.

Asset management.

9.2 Scan plane
The scan plane includes:

Agent service.

Nmap engine.

OpenVAS engine.

Nuclei engine.

Plugin engine.

Orchestration requirement: For every triggered scan (internal or external), the scan plane must launch Nuclei and OpenVAS as independent, non-blocking parallel jobs against the same target. A failure or delay in one engine must not affect the execution, status, or findings of the other engine.

9.3 Communication
Communication between control plane and scan plane is defined as:

HTTPS.

Mutual TLS.

10. Deployment model
10.1 External scanner deployment
External OpenVAS agent deployed on AWS EC2.

External Nuclei execution deployed alongside, running in parallel against the same external targets.

10.2 Internal scanner deployment
Internal OpenVAS agent deployed with Docker on Linux VM inside internal network.

Internal Nuclei execution deployed alongside, running in parallel against the same internal targets.

Known infrastructure note: OpenVAS (GVMD) connectivity/socket stability is not yet fully resolved as of this PRD update. Per client direction, the dual-engine parallel architecture must be implemented first; OpenVAS infrastructure stabilization continues as a parallel workstream and must not block the architecture rollout. The system must gracefully handle OpenVAS being unavailable per the failure-handling rules in Section 7.4.

Data model
11. MVP database entities
11.1 Assets
Fields: Asset ID, Hostname, IP Address, Environment, Criticality.

11.2 Scans
Fields: Scan ID, Type, Overall Status, Start Time, End Time.

11.3 Scan Engine Executions (NEW)
To support dual-engine parallel execution, each scan must have two associated engine execution records:

Fields:

Execution ID.

Scan ID (foreign key).

Engine Name (Nuclei / OpenVAS).

Engine Status (Queued, Running, Completed, Failed).

Start Time.

End Time.

Progress (%).

Failure Reason (nullable).

11.4 Findings
Fields: Asset, Severity, CVE, Description, Recommendation, Engine Execution ID (foreign key — used internally for structural separation, not displayed as a UI tag).

12. Suggested minimal supporting entities
To support the defined flow without going out of scope, the MVP may also include:

Agents.

Reports.

Scan targets or scan-to-asset mapping.

These supporting entities are implementation helpers for the required features, not feature expansion.

Non-functional requirements
13. Targets
The MVP target values are:

10,000 assets.

100 concurrent scans.

50 agents.

99.5% availability.

Each concurrent scan involves 2 parallel engine executions (Nuclei + OpenVAS), so effective concurrent engine job capacity should be planned at up to 200 parallel executions.

14. Security for v1
The original scope mentions JWT authentication, RBAC, TLS encryption, mutual TLS, and audit logging.

For this PRD version:

Excluded for now: user login, JWT auth, RBAC.

Retained because part of architecture: HTTPS and mutual TLS for agent communication.

Optional later phase: audit logging UI and user-based authorization.

This keeps the product simple while preserving the scan-plane communication requirement.

Deliverables
15. MVP deliverables
Release 1

Flask control plane.

PostgreSQL.

Agent registration or presence tracking.

Release 2

Nmap integration.

Asset discovery.

Internal scanning (Nuclei + OpenVAS parallel execution).

Release 3

OpenVAS integration (internal + external).

Nuclei integration (internal + external), running in parallel with OpenVAS for both scan types.

Dual-engine status/progress tracking and separated findings display.

PCI-oriented checks.

Reporting (with per-engine findings sections).

Dashboard.

Out of scope
16. Explicitly out of scope for this MVP PRD
The following must not be included in this version:

Login and authentication UI.

RBAC and roles enforcement.

Multi-tenancy.

Compliance automation.

SIEM integrations.

Ticketing integrations.

Automated remediation.

AI risk prioritization.

Official PCI ASV certification workflow.

Dispute handling workflow.

Digital signatures and attestation workflow.

Advanced production-scale orchestration beyond the defined flow.

Merging or tagging findings between engines into a single combined list.

A single blanket pass/fail scan status that hides individual engine outcomes.

Success criteria
17. MVP success criteria
Within first deployment, success means:

Discover 95% or more reachable assets.

Successfully complete 95% of scheduled scans (where "successfully complete" means both engine executions reach a final state — Completed or Failed — with truthful per-engine results, not fabricated success).

Generate reports in under 60 seconds.

Detect known CVEs identified by OpenVAS and known issues identified by Nuclei templates.

Produce PCI-oriented vulnerability assessment reports with clearly separated Nuclei and OpenVAS findings.

Acceptance criteria
18. Functional acceptance criteria
User can add assets manually into inventory.

User can create an internal scan.

User can create an external scan.

Both internal and external scans trigger Nuclei and OpenVAS in parallel automatically.

Internal scans route through the presence agent path for OpenVAS execution.

External scans route to external OpenVAS, alongside Nuclei execution.

If one engine fails while the other succeeds, the successful engine's findings are still saved and displayed, and the failed engine shows its real failure reason — the scan is not marked as a total failure.

Findings are saved and displayed separately per engine (Nuclei section, OpenVAS section), never merged.

Scan detail view shows two independent progress indicators — one for Nuclei, one for OpenVAS — reflecting real-time per-engine status.

Reports can be downloaded in PDF and CSV, with findings sections separated by engine.

Dashboard shows overall scan status (computed per Section 7.4 logic) and agent presence.

Notes
19. Implementation notes
This PRD intentionally removes login for now because it was explicitly requested to be deferred. The product should be built as a simple operational MVP first, following the exact shared flow and current written scope only.

v1.1 update note: Per confirmed client direction (August 2026), the scan architecture has changed from "one engine per scan type" to "both engines per scan type, running in parallel." This is a scope change, not a scope expansion — no new compliance, authentication, or integration features are introduced. The priority sequencing is: (1) implement the dual-engine parallel architecture and its data model/status/UI support first, (2) continue resolving OpenVAS/GVMD infrastructure stability issues alongside, without blocking the architecture work.