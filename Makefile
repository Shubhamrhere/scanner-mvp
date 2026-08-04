# ──────────────────────────────────────────────────────────────
# Distributed Vulnerability Scan Orchestration Engine
# Makefile — Developer Shortcuts
# ──────────────────────────────────────────────────────────────

.PHONY: help up down restart build logs \
        api-logs worker-logs db-logs \
        migrate migrate-create migrate-downgrade \
        seed create-admin \
        test test-cov lint format \
        frontend-dev frontend-build \
        clean clean-volumes \
        shell db-shell redis-shell

# ── Default ──────────────────────────────────────────────────

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Docker Compose ───────────────────────────────────────────

up: ## Start all services
	docker compose up -d

up-build: ## Build and start all services
	docker compose up -d --build

down: ## Stop all services
	docker compose down

restart: ## Restart all services
	docker compose restart

build: ## Build all images
	docker compose build

logs: ## Tail all service logs
	docker compose logs -f

api-logs: ## Tail API logs
	docker compose logs -f api

worker-logs: ## Tail worker logs
	docker compose logs -f worker

db-logs: ## Tail PostgreSQL logs
	docker compose logs -f postgres

# ── Database ─────────────────────────────────────────────────

migrate: ## Run database migrations
	docker compose exec api alembic upgrade head

migrate-create: ## Create a new migration (usage: make migrate-create MSG="add users table")
	docker compose exec api alembic revision --autogenerate -m "$(MSG)"

migrate-downgrade: ## Downgrade one migration
	docker compose exec api alembic downgrade -1

migrate-history: ## Show migration history
	docker compose exec api alembic history

seed: ## Seed database with development data
	docker compose exec api python -m scripts.seed_db

create-admin: ## Create initial admin user
	docker compose exec api python -m scripts.create_admin

# ── Testing ──────────────────────────────────────────────────

test: ## Run backend tests
	docker compose exec api pytest tests/ -v

test-cov: ## Run tests with coverage
	docker compose exec api pytest tests/ -v --cov=app --cov-report=html --cov-report=term

test-local: ## Run tests locally (without Docker)
	cd backend && python -m pytest tests/ -v

# ── Linting / Formatting ────────────────────────────────────

lint: ## Run all linters
	cd backend && ruff check app/ tests/
	cd frontend && npm run lint

format: ## Format all code
	cd backend && ruff format app/ tests/
	cd backend && isort app/ tests/
	cd frontend && npm run format

typecheck: ## Run type checking
	cd backend && mypy app/

# ── Frontend ─────────────────────────────────────────────────

frontend-dev: ## Start frontend dev server locally
	cd frontend && npm run dev

frontend-build: ## Build frontend for production
	cd frontend && npm run build

frontend-install: ## Install frontend dependencies
	cd frontend && npm install

# ── Shells ───────────────────────────────────────────────────

shell: ## Open a shell in the API container
	docker compose exec api /bin/bash

db-shell: ## Open PostgreSQL shell
	docker compose exec postgres psql -U vulnscan -d vulnscan

redis-shell: ## Open Redis CLI
	docker compose exec redis redis-cli

# ── Cleanup ──────────────────────────────────────────────────

clean: ## Stop and remove containers
	docker compose down --remove-orphans

clean-volumes: ## Stop and remove containers AND volumes (destroys data)
	docker compose down --volumes --remove-orphans

# ── Setup ────────────────────────────────────────────────────

setup: ## First-time setup: copy env, install deps, build, migrate
	@echo "==> Copying .env.example to .env"
	@cp -n .env.example .env 2>/dev/null || true
	@echo "==> Building Docker images"
	docker compose build
	@echo "==> Starting services"
	docker compose up -d
	@echo "==> Waiting for services to be healthy..."
	@sleep 10
	@echo "==> Running migrations"
	docker compose exec api alembic upgrade head
	@echo "==> Setup complete! Run 'make logs' to view service output."
