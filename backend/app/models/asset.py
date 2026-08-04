"""
Asset model — scan targets: IPs, domains, servers, applications (§32).
"""

import uuid
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.organization_id"),
        nullable=False,
        index=True,
    )
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv4/IPv6
    asset_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # external, internal, web_application, database, server
    environment: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    criticality: Mapped[str] = mapped_column(
        String(50), default="medium", nullable=False
    )  # low, medium, high, critical
    discovered_source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    organization: Mapped["Organization"] = relationship(  # noqa: F821
        "Organization", back_populates="assets"
    )
    scan_jobs: Mapped[list] = relationship("ScanJob", back_populates="asset")
    findings: Mapped[list] = relationship("Finding", back_populates="asset")

    def __repr__(self) -> str:
        return (
            f"<Asset(id={self.asset_id}, hostname='{self.hostname}', "
            f"ip='{self.ip_address}', type='{self.asset_type}')>"
        )
