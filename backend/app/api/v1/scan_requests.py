"""Scan requests routes. Implementation: Phase 4."""
from fastapi import APIRouter
router = APIRouter()

@router.post("")
async def create_scan_request():
    """Create a new scan request. [Phase 4]"""
    return {"message": "Create scan request — Phase 4"}

@router.get("")
async def list_scan_requests():
    """List scan requests. [Phase 4]"""
    return {"message": "List scan requests — Phase 4"}
