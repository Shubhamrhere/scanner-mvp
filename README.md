# Distributed Vulnerability Scan Orchestration Engine

A production-grade, distributed orchestration engine for running, managing, and reporting on vulnerability scans across large-scale environments.

## Project Overview

This platform decouples business logic from actual scanning tools. It operates through a centralized **Control Plane** (API, Database, Task Queues) that assigns scan jobs to a distributed **Scanner Plane** (Agents running tools like Nmap, OpenVAS, Nuclei, ZAP). 

The platform supports compliance requirements, multi-tenancy (organizations), role-based access control, distributed state locking to prevent redundant scanning, and automated report generation (PDF/CSV) backed by immutable object storage.

## Architecture Summary

- **Control Plane**: 
  - FastAPI-based REST API.
  - Celery-based workers for job queuing, event scheduling, and aggregation.
  - Redis distributed locking (`lock:asset:<id>`) ensures an asset is never scanned concurrently by multiple agents.
- **Scanner Plane**: 
  - Independent, pluggable Agents that heartbeat to the Control Plane.
  - Agents fetch jobs, execute underlying scanner adapters, and stream results back.
- **Data Layer**:
  - **PostgreSQL**: The durable source of truth (users, assets, findings, schedules, audit logs).
  - **Redis**: Transient state (locks, celery queues, agent heartbeats).
  - **S3 / MinIO**: Object storage for raw scan outputs, generated reports, and customer dispute evidence.

## Core Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy (async), Alembic, Pydantic, Celery.
- **Frontend**: React, TypeScript, Vite, Tailwind CSS, TanStack Query, Zustand.
- **Infrastructure**: PostgreSQL 16, Redis 7, MinIO (S3-compatible).

## Local Development Setup

To run the platform locally, you will need **Docker** and **Docker Compose**.

1. **Environment Variables**:
   Copy the example environment files to configure your secrets locally.
   ```bash
   cp .env.example .env
   cp backend/.env.example backend/.env
   cp frontend/.env.example frontend/.env
   ```
   *(Note: NEVER commit `.env` files. Ensure they are covered by `.gitignore`.)*

2. **Start the Stack**:
   We provide a Makefile with developer shortcuts. Run:
   ```bash
   make setup
   ```
   This will build the Docker images, start PostgreSQL, Redis, MinIO, the API, the Celery workers, and the frontend dev server, and then run the database migrations.

3. **Access Services**:
   - Frontend UI: http://localhost:5173
   - API Docs (Swagger): http://localhost:8000/docs
   - MinIO Console: http://localhost:9001 (default: minioadmin / minioadmin)

## Environment Variable Guidance

The core `.env` file controls Docker compose and global settings. The `backend` and `frontend` folders can also hold specific `.env` files for localized configuration. The system expects you to rotate the `JWT_SECRET_KEY` and PostgreSQL passwords before moving anywhere near production.

## Repository Structure

```
├── backend/            # FastAPI Control Plane and Celery Workers
│   ├── alembic/        # Database migrations
│   ├── app/            # Source code (API routers, core models, services)
│   └── Dockerfile
├── frontend/           # React/Vite UI Dashboard
│   ├── src/            # Components, pages, hooks, state
│   └── Dockerfile
├── infra/              # External config (nginx, postgres init scripts)
├── Makefile            # Developer command shortcuts
├── docker-compose.yml  # Local full-stack definition
└── TASKS.md            # Current implementation progress
```

## Security Note

**Important**: This engine orchestrates actual security scanning tools. 
- Agents may have access to privileged network segments. 
- Raw scan outputs (artifacts) may contain highly sensitive infrastructure data (open ports, identified vulnerabilities, credentials found in web app scans).
- The `minio-data/` volume and all PostgreSQL volumes MUST be strictly protected.
- Never hardcode API keys for external integrations (e.g., NVD API, Slack, JIRA) in the source code. Always use environment variables or a secrets manager.

## Current Phase

The project is currently in the **Bootstrap Phase (Phase 0)**. The repository structure is fully defined, base database models are configured, and the environment is ready for Domain API implementation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development rules, PR guidelines, and code style expectations.
