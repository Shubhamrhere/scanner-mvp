"""
Authentication routes — login, token refresh.
Implementation: Phase 1.
"""

from fastapi import APIRouter

router = APIRouter()


@router.post("/login")
async def login():
    """Authenticate user and return JWT tokens. [Phase 1]"""
    # Implemented in Phase 1
    return {"message": "Auth endpoint — Phase 1 implementation"}


@router.post("/refresh")
async def refresh_token():
    """Refresh an expired access token. [Phase 1]"""
    return {"message": "Token refresh — Phase 1 implementation"}
