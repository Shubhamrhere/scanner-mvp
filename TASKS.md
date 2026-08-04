# TASKS.md — Distributed Vulnerability Scan Orchestration Engine

## Phase 0 — Repository Bootstrap
- [x] Create full directory structure
- [x] Create backend dependency files (pyproject.toml, requirements.txt)
- [x] Create frontend package.json with all dependencies
- [x] Create Docker Compose (PostgreSQL, Redis, MinIO, API, worker, scheduler)
- [x] Create Makefile
- [x] Create .env.example
- [x] Create .pre-commit-config.yaml
- [x] Create .gitignore
- [x] Create README.md
- [x] Install all dependencies
- [x] Verify Docker Compose starts cleanly

## Phase 1 — Foundations
- `[ ]` FastAPI app bootstrap with middleware and structured logging
- `[ ]` All SQLAlchemy models
- `[ ]` Alembic initial migration
- `[ ]` JWT authentication
- `[ ]` RBAC middleware
- `[ ]` User + Organization CRUD
- `[ ]` Health endpoints
- `[ ]` Audit logging service
- `[ ]` Frontend Vite + React bootstrap
- `[ ]` Login page
- `[ ]` Dashboard shell with role-based navigation

## Phase 2 — Core Platform
- `[ ]` Asset CRUD with org scoping
- `[ ]` Scope intake service
- `[ ]` Discovery service scaffolding
- `[ ]` Scan request creation
- `[ ]` Scan/Job lifecycle state machine
- `[ ]` Orchestrator engine
- `[ ]` Scheduler service (Celery periodic)
- `[ ]` Distributed Lock Manager
- `[ ]` Agent registration + heartbeat
- `[ ]` Redis queue integration
- `[ ]` Frontend: scope, discovery, queue, agent views

## Phase 3 — Scanner Orchestration
- `[ ]` Scanner adapter framework
- `[ ]` Nmap, OpenVAS, Nuclei, ZAP, testssl adapters
- `[ ]` Python plugin framework
- `[ ]` Pipeline DAG (external + internal)
- `[ ]` Job dispatch flow
- `[ ]` Result upload API
- `[ ]` Frontend: external/internal scan workflows, job detail

## Phase 4 — Findings Pipeline
- `[ ]` Findings aggregator + normalization
- `[ ]` Deduplication
- `[ ]` CVSS scoring service
- `[ ]` PCI rule engine
- `[ ]` Remediation enrichment
- `[ ]` Frontend: findings list/detail, CVSS/PCI review

## Phase 5 — ASV Workflow
- `[ ]` Report generation (Attestation, Summary, Vulnerability Detail)
- `[ ]` Report lifecycle (Draft → Under Review → Final)
- `[ ]` PDF/CSV export
- `[ ]` MinIO storage integration
- `[ ]` Dispute/evidence workflow
- `[ ]` ASV analyst review
- `[ ]` Audit trail
- `[ ]` Frontend: reports, disputes, analyst review

## Phase 6 — Hardening
- `[ ]` Integration tests
- `[ ]` Celery retry improvements
- `[ ]` Agent health monitoring
- `[ ]` Logging + correlation IDs
- `[ ]` Error handling polish
- `[ ]` OpenTelemetry scaffolding
- `[ ]` Scan schedules (quarterly/monthly/weekly)
- `[ ]` Retention cleanup worker
- `[ ]` Deployment docs
- `[ ]` Production-readiness checklist
