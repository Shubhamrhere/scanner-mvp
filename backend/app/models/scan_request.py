"""
Scan Request model — user intent to scan assets (§34).
States: pending, approved, scheduled, completed, cancelled.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanRequest(Base):
    __tablename__ = "scan_requests"

    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.organization_id"),
        nullable=False,
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id"),
        nullable=False,
    )
    scan_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # external_pci, internal, full
    status: Mapped[str] = mapped_column(
        String(50), default="pending", nullable=False
    )  # pending, approved, scheduled, completed, cancelled
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(  # noqa: F821
        "Organization", back_populates="scan_requests"
    )
    requested_by_user: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="scan_requests"
    )
    scans: Mapped[list] = relationship("Scan", back_populates="scan_request")

    def __repr__(self) -> str:
        return (
            f"<ScanRequest(id={self.request_id}, type='{self.scan_type}', "
            f"status='{self.status}')>"
        )
