"""Scans routes. Implementation: Phase 4."""
from fastapi import APIRouter
router = APIRouter()

@router.get("")
async def list_scans():
    """List scans. [Phase 4]"""
    return {"message": "List scans — Phase 4"}

@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan status. [Phase 4]"""
    return {"message": f"Scan {scan_id} — Phase 4"}
