"""
Scan Job model — individual asset-level pipeline execution (§36).
States: pending, lock_wait, running, aggregating, completed, failed, retry_scheduled, aborted.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.scan_id"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.asset_id"),
        nullable=False,
    )
    current_stage: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # nmap, openvas, nuclei, zap, testssl, plugins, aggregation
    status: Mapped[str] = mapped_column(
        String(50), default="pending", nullable=False, index=True
    )  # pending, lock_wait, running, aggregating, completed, failed, retry_scheduled, aborted
    priority: Mapped[int] = mapped_column(
        Integer, default=5, nullable=False
    )  # 1 = highest, 10 = lowest
    assigned_agent: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id"),
        nullable=True,
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="jobs")  # noqa: F821
    asset: Mapped["Asset"] = relationship("Asset", back_populates="scan_jobs")  # noqa: F821
    agent: Mapped[Optional["Agent"]] = relationship("Agent")  # noqa: F821
    executions: Mapped[list] = relationship(
        "JobExecution", back_populates="job", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<ScanJob(id={self.job_id}, status='{self.status}', "
            f"stage='{self.current_stage}', priority={self.priority})>"
        )
