"""
Agent Capability model — scanner tool declarations per agent (§33.2).
"""

import uuid
from typing import Optional

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AgentCapability(Base):
    __tablename__ = "agent_capabilities"

    capability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id"),
        nullable=False,
    )
    capability_name: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # nmap, openvas, nuclei, zap, testssl, python_plugin
    version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Relationships
    agent: Mapped["Agent"] = relationship("Agent", back_populates="capabilities")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AgentCapability(agent={self.agent_id}, tool='{self.capability_name}')>"
