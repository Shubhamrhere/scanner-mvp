"""
Scan Schedule model — recurring scan configuration (§50).
Frequencies: quarterly, monthly, weekly, custom.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    schedule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )
    scan_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # external_pci, internal, full
    frequency: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # quarterly, monthly, weekly, custom
    cron_expression: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # For custom schedules
    next_run: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_run: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(  # noqa: F821
        "Organization", back_populates="scan_schedules"
    )

    def __repr__(self) -> str:
        return (
            f"<ScanSchedule(id={self.schedule_id}, type='{self.scan_type}', "
            f"freq='{self.frequency}', enabled={self.enabled})>"
        )
