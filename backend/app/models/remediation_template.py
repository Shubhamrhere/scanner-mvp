"""
Remediation Template model — curated fix guidance for rule-based findings (§44).
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RemediationTemplate(Base):
    __tablename__ = "remediation_templates"

    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    rule_key: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False
    )  # e.g., smb_v1_enabled, missing_hsts
    title: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_text: Mapped[str] = mapped_column(Text, nullable=False)
    severity_context: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    reference_links: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<RemediationTemplate(key='{self.rule_key}', title='{self.title[:50]}')>"
