"""Scope intake routes. Implementation: Phase 2."""
from fastapi import APIRouter
router = APIRouter()

@router.post("/submit")
async def submit_scope():
    """Submit scan scope (IPs, CIDRs, FQDNs). [Phase 2]"""
    return {"message": "Scope submission — Phase 2"}

@router.get("/{scope_id}")
async def get_scope(scope_id: str):
    """Get scope details. [Phase 2]"""
    return {"message": f"Scope {scope_id} — Phase 2"}
