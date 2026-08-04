"""Scan jobs routes. Implementation: Phase 4."""
from fastapi import APIRouter
router = APIRouter()

@router.get("")
async def list_jobs():
    """List jobs. [Phase 4]"""
    return {"message": "List jobs — Phase 4"}

@router.get("/{job_id}")
async def get_job(job_id: str):
    """Get job details. [Phase 4]"""
    return {"message": f"Job {job_id} — Phase 4"}
