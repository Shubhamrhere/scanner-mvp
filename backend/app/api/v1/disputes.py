"""Disputes routes. Implementation: Phase 5."""
from fastapi import APIRouter
router = APIRouter()

@router.post("")
async def create_dispute():
    """Submit a dispute. [Phase 5]"""
    return {"message": "Create dispute — Phase 5"}

@router.get("")
async def list_disputes():
    """List disputes. [Phase 5]"""
    return {"message": "List disputes — Phase 5"}
