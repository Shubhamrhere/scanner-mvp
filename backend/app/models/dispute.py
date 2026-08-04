"""
Dispute model — customer challenge of findings (§46).
Types: false_positive, compensating_control.
Decisions: pending, approved, rejected.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Dispute(Base):
    __tablename__ = "disputes"

    dispute_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.finding_id"),
        nullable=False,
    )
    submitted_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id"),
        nullable=False,
    )
    dispute_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # false_positive, compensating_control
    evidence_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_file_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id"),
        nullable=True,
    )
    decision: Mapped[str] = mapped_column(
        String(50), default="pending", nullable=False
    )  # pending, approved, rejected
    decision_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="disputes")  # noqa: F821
    submitter: Mapped["User"] = relationship("User", foreign_keys=[submitted_by])  # noqa: F821
    reviewer: Mapped[Optional["User"]] = relationship(  # noqa: F821
        "User", foreign_keys=[reviewed_by]
    )

    def __repr__(self) -> str:
        return (
            f"<Dispute(id={self.dispute_id}, type='{self.dispute_type}', "
            f"decision='{self.decision}')>"
        )
