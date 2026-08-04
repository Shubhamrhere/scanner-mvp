"""
Finding model — normalized vulnerability records (§40, §41, §44).
"""

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    finding_id: Mapped[uuid.UUID] = mapped_column(
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
    source_tool: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # nmap, openvas, nuclei, zap, testssl, plugin
    vulnerability_id: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )  # CVE identifier
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # critical, high, medium, low, info
    cvss_score: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(3, 1), nullable=True
    )
    cvss_source: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # nvd, openvas, manual
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # tcp, udp
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False
    )  # open, disputed, approved_exception, fixed, closed
    is_auto_fail: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )  # PCI automatic failure flag

    # Remediation engine fields (§44)
    rule_key: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    remediation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_templates.template_id"),
        nullable=True,
    )

    # Temporal tracking
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Deduplication hash — combination of CVE + asset + port + tool for matching
    dedup_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")  # noqa: F821
    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")  # noqa: F821
    remediation_template: Mapped[Optional["RemediationTemplate"]] = relationship(  # noqa: F821
        "RemediationTemplate"
    )
    disputes: Mapped[list] = relationship("Dispute", back_populates="finding")

    def __repr__(self) -> str:
        return (
            f"<Finding(id={self.finding_id}, title='{self.title[:50]}', "
            f"severity='{self.severity}', cvss={self.cvss_score})>"
        )
