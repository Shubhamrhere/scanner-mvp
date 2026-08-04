"""
Root API router — aggregates all v1 sub-routers.
"""

from fastapi import APIRouter

from app.api.v1 import (
    agents,
    assets,
    auth,
    discovery,
    disputes,
    findings,
    health,
    jobs,
    organizations,
    reports,
    scan_requests,
    scans,
    scope_intake,
    users,
)

api_router = APIRouter()

# ── Health (no auth required) ──
api_router.include_router(health.router, prefix="/health", tags=["Health"])

# ── Authentication ──
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# ── Users & Organizations ──
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(
    organizations.router, prefix="/organizations", tags=["Organizations"]
)

# ── Assets & Scope ──
api_router.include_router(assets.router, prefix="/assets", tags=["Assets"])
api_router.include_router(scope_intake.router, prefix="/scope", tags=["Scope Intake"])
api_router.include_router(discovery.router, prefix="/discovery", tags=["Discovery"])

# ── Scans ──
api_router.include_router(
    scan_requests.router, prefix="/scan-requests", tags=["Scan Requests"]
)
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(jobs.router, prefix="/jobs", tags=["Jobs"])

# ── Agents ──
api_router.include_router(agents.router, prefix="/agents", tags=["Agents"])

# ── Findings & Disputes ──
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])
api_router.include_router(disputes.router, prefix="/disputes", tags=["Disputes"])

# ── Reports ──
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
