# Scanner MVP

**Scanner MVP** is a distributed vulnerability assessment platform with a Flask-based control plane, designed for managing internal and external vulnerability scans, tracking findings, and generating PDF/CSV reports.

## Features

- **Dashboard:** A interface for high-density summary metrics (Assets, Active Scans, Findings, Agent Status).
- **Asset Inventory:** Manage target endpoints (IPs/Hostnames) for scanning.
- **Scan Scheduling:** Execute internal (via Presence Agent) and external scans asynchronously using Celery and Redis.
- **Findings Explorer:** Track vulnerabilities found, displaying severity and descriptions.
- **Reporting:** Export vulnerabilities into PDF (via `wkhtmltopdf`) and CSV formats.
- **Agent Management:** View deployed agents and their connection statuses.

## Architecture

1. **Flask (Web App):** The control plane and user interface.
2. **Celery Worker:** Handles asynchronous scan tasks and report generation.
3. **Redis:** Message broker and result backend for Celery.
4. **PostgreSQL:** Primary database to store assets, scans, findings, and agents.
5. **OpenVAS (Greenbone):** Vulnerability scanner container orchestration.

## Getting Started

The entire environment runs via Docker Compose.

### Prerequisites
- Docker & Docker Compose

### Quick Start
1. Clone this repository.
2. Run `docker compose up -d --build`.
3. Open your browser to `http://localhost:5000`.

### Database & Background Tasks
- Postgres runs locally on port `5432` internally.
- Redis handles the celery tasks in the background.
