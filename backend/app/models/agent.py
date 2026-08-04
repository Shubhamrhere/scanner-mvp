"""
Agent model — scanner worker registration (§33.1).
States: online, offline, draining, maintenance.
"""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.organization_id"),
        nullable=True,
    )
    agent_name: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # external, internal
    status: Mapped[str] = mapped_column(
        String(50), default="offline", nullable=False, index=True
    )  # online, offline, draining, maintenance
    max_concurrency: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    current_load: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # Relationships
    organization: Mapped[Optional["Organization"]] = relationship(  # noqa: F821
        "Organization", back_populates="agents"
    )
    capabilities: Mapped[List["AgentCapability"]] = relationship(  # noqa: F821
        "AgentCapability", back_populates="agent", cascade="all, delete-orphan"
    )
    job_executions: Mapped[list] = relationship("JobExecution", back_populates="agent")

    def __repr__(self) -> str:
        return (
            f"<Agent(id={self.agent_id}, name='{self.agent_name}', "
            f"type='{self.agent_type}', status='{self.status}')>"
        )
