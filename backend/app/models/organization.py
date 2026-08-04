"""
Organization model — multi-tenant customer entity (§30).
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False)

    # Relationships
    users: Mapped[List["User"]] = relationship(  # noqa: F821
        "User", back_populates="organization", cascade="all, delete-orphan"
    )
    assets: Mapped[List["Asset"]] = relationship(  # noqa: F821
        "Asset", back_populates="organization", cascade="all, delete-orphan"
    )
    agents: Mapped[List["Agent"]] = relationship(  # noqa: F821
        "Agent", back_populates="organization"
    )
    scan_requests: Mapped[List["ScanRequest"]] = relationship(  # noqa: F821
        "ScanRequest", back_populates="organization"
    )
    scan_schedules: Mapped[List["ScanSchedule"]] = relationship(  # noqa: F821
        "ScanSchedule", back_populates="organization"
    )

    def __repr__(self) -> str:
        return f"<Organization(id={self.organization_id}, name='{self.name}')>"
