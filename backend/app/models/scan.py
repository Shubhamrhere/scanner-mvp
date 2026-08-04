"""
Scan model — execution instance generated from a scan request (§35).
States: created, running, completed, failed, partial.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_requests.request_id"),
        nullable=False,
        index=True,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="created", nullable=False
    )  # created, running, completed, failed, partial
    overall_result: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # pass, fail
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan_request: Mapped["ScanRequest"] = relationship(  # noqa: F821
        "ScanRequest", back_populates="scans"
    )
    jobs: Mapped[list] = relationship("ScanJob", back_populates="scan")
    findings: Mapped[list] = relationship("Finding", back_populates="scan")
    reports: Mapped[list] = relationship("Report", back_populates="scan")

    def __repr__(self) -> str:
        return f"<Scan(id={self.scan_id}, status='{self.status}')>"
