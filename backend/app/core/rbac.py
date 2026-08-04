"""
Role-Based Access Control (RBAC) dependencies.
Enforces Admin, Analyst, Executive role boundaries.
"""

from enum import Enum
from functools import wraps
from typing import List

import structlog
from fastapi import Depends, HTTPException, status

from app.core.auth import get_current_active_user
from app.models.user import User

logger = structlog.get_logger()


class Role(str, Enum):
    """Platform roles as defined in the architecture document (§31)."""

    ADMIN = "admin"
    ANALYST = "analyst"
    EXECUTIVE = "executive"


def require_roles(allowed_roles: List[Role]):
    """
    FastAPI dependency that checks if the current user has one of the allowed roles.

    Usage:
        @router.get("/admin-only", dependencies=[Depends(require_roles([Role.ADMIN]))])
        async def admin_endpoint():
            ...
    """

    async def role_checker(
        current_user: User = Depends(get_current_active_user),
    ) -> User:
        if current_user.role not in [role.value for role in allowed_roles]:
            logger.warning(
                "rbac_access_denied",
                user_id=str(current_user.user_id),
                user_role=current_user.role,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return role_checker


# ── Convenience dependencies ──

require_admin = require_roles([Role.ADMIN])
require_analyst = require_roles([Role.ADMIN, Role.ANALYST])
require_any_role = require_roles([Role.ADMIN, Role.ANALYST, Role.EXECUTIVE])
