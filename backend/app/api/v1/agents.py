"""Agents routes. Implementation: Phase 3."""
from fastapi import APIRouter
router = APIRouter()

@router.get("")
async def list_agents():
    """List agents. [Phase 3]"""
    return {"message": "List agents — Phase 3"}

@router.post("/register")
async def register_agent():
    """Register agent. [Phase 3]"""
    return {"message": "Register agent — Phase 3"}

@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str):
    """Agent heartbeat. [Phase 3]"""
    return {"message": f"Heartbeat for agent {agent_id} — Phase 3"}
