"""
FastAPI application factory.
Creates and configures the main application instance.
"""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.config import get_settings
from app.core.logging import configure_logging
from app.core.middleware import RequestLoggingMiddleware
from app.db.session import engine

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager — startup and shutdown events."""
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)

    logger.info(
        "application_startup",
        app_name=settings.app_name,
        app_version=settings.app_version,
        environment=settings.app_env,
    )

    yield

    # Shutdown: dispose database engine
    await engine.dispose()
    logger.info("application_shutdown")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="VulnScan Orchestration Engine",
        description=(
            "Distributed Vulnerability Scan Orchestration Engine — "
            "Control Plane API for managing scan lifecycle, agents, "
            "findings, and compliance reports."
        ),
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Custom Middleware ──
    app.add_middleware(RequestLoggingMiddleware)

    # ── Routers ──
    app.include_router(api_router, prefix=settings.api_v1_prefix)

    return app


# Application instance used by uvicorn
app = create_app()
