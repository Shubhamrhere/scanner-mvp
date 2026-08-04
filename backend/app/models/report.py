"""
Report model — compliance report metadata (§47, §48, §49).
Types: attestation, summary, vulnerability_detail.
Formats: PDF, CSV.
Lifecycle: draft, under_review, final.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Report(Base):
    __tablename__ = "reports"

    report_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.scan_id"),
        nullable=False,
    )
    report_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # attestation, summary, vulnerability_detail
    format: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # pdf, csv
    status: Mapped[str] = mapped_column(
        String(50), default="draft", nullable=False
    )  # draft, under_review, final
    storage_location: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # MinIO/S3 object key
    overall_result: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # pass, fail
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id"),
        nullable=True,
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    retention_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )  # 3-year retention per §49

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")  # noqa: F821
    reviewer_user: Mapped[Optional["User"]] = relationship("User")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<Report(id={self.report_id}, type='{self.report_type}', "
            f"format='{self.format}', status='{self.status}')>"
        )
