"""
Job Execution model — immutable record of each execution attempt (§37).
A single job may have multiple execution attempts due to retries.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class JobExecution(Base):
    __tablename__ = "job_executions"

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.job_id"),
        nullable=False,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.agent_id"),
        nullable=False,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # running, completed, failed, timeout
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    result_location: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # S3/MinIO path to raw results
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="executions")  # noqa: F821
    agent: Mapped["Agent"] = relationship(  # noqa: F821
        "Agent", back_populates="job_executions"
    )

    def __repr__(self) -> str:
        return (
            f"<JobExecution(id={self.execution_id}, job={self.job_id}, "
            f"attempt={self.attempt_number}, status='{self.status}')>"
        )
