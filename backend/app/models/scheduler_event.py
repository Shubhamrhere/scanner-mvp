"""
Scheduler Event model — scheduler observability (§52).
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SchedulerEvent(Base):
    __tablename__ = "scheduler_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.job_id"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # JOB_CREATED, LOCK_ACQUIRED, AGENT_SELECTED, JOB_FAILED, RETRY_SCHEDULED, LOCK_RELEASED
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSONB, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<SchedulerEvent(id={self.event_id}, type='{self.event_type}')>"
