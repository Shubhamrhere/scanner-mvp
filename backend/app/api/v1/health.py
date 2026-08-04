"""
Health check endpoints — no authentication required.
"""

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.dependencies import get_db

router = APIRouter()
logger = structlog.get_logger()


@router.get("")
async def health_check():
    """Basic liveness check."""
    settings = get_settings()
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """
    Readiness check — verifies database connectivity.
    Returns 503 if dependencies are unavailable.
    """
    checks = {"database": False, "timestamp": datetime.now(timezone.utc).isoformat()}

    try:
        result = await db.execute(text("SELECT 1"))
        checks["database"] = result.scalar() == 1
    except Exception as e:
        logger.error("readiness_check_failed", component="database", error=str(e))
        checks["database_error"] = str(e)

    all_healthy = all(v for k, v in checks.items() if isinstance(v, bool))

    if not all_healthy:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "checks": checks},
        )

    return {"status": "ready", "checks": checks}
