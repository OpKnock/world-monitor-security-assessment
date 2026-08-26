"""Normalized single-database ORM models (spec §15).

All time columns are timezone-aware UTC.  UUIDs are stored as 32-char
hex strings (``uuid4().hex``) for portability across SQLite / Postgres.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uuid() -> str:
    """Return a 32-char hex UUID4 suitable for primary keys."""
    return uuid.uuid4().hex


def _now() -> datetime:
    """Current UTC timestamp (timezone-aware)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Mixins
# ---------------------------------------------------------------------------


class TimestampMixin:
    """``created_at`` / ``updated_at`` columns shared by every table."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )


# ---------------------------------------------------------------------------
# Enumerations as check constraints (SQLite does not have native enums)
# ---------------------------------------------------------------------------

_ROLE_VALUES = ("admin", "analyst", "viewer")
_ASSESSMENT_STATUS_VALUES = ("queued", "running", "completed", "failed")
_SCAN_RUN_STATUS_VALUES = ("queued", "running", "completed", "failed", "skipped")
_FINDING_SEVERITY_VALUES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
_FINDING_STATUS_VALUES = ("OPEN", "CONFIRMED", "FALSE_POSITIVE", "REMEDIATED", "RETESTED")
_REPORT_FORMAT_VALUES = ("pdf", "json", "md", "csv")

# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


class User(Base, TimestampMixin):
    """Platform account (local auth only)."""

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(f"role IN {str(_ROLE_VALUES)}", name="ck_users_role"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="viewer", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} role={self.role}>"


class Target(Base, TimestampMixin):
    """Known assessment target URL (deduplication aid)."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True, nullable=False)
    label: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    first_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assessment_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<Target id={self.id} url={self.url[:80]!r}>"


class Assessment(Base, TimestampMixin):
    """A grouping of scanner runs against a single target / source snapshot."""

    __tablename__ = "assessments"
    __table_args__ = (
        CheckConstraint(f"status IN {str(_ASSESSMENT_STATUS_VALUES)}", name="ck_assessments_status"),
        Index("ix_assessments_user_status", "user_id", "status"),
        Index("ix_assessments_target_status", "target", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    source_path: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    modules: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    module_targets: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True, nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    user: Mapped[User] = relationship(lazy="joined")
    scan_runs: Mapped[list[ScanRun]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<Assessment id={self.id} target={self.target[:60]!r} status={self.status}>"


class ScanRun(Base, TimestampMixin):
    """Execution record for a single scanner module within an assessment."""

    __tablename__ = "scan_runs"
    __table_args__ = (
        CheckConstraint(f"status IN {str(_SCAN_RUN_STATUS_VALUES)}", name="ck_scan_runs_status"),
        Index("ix_scan_runs_assessment_status", "assessment_id", "status"),
        Index("ix_scan_runs_scanner", "scanner"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checks_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checks_safe: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_output_path: Mapped[str] = mapped_column(String(1024), default="", nullable=False)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assessment: Mapped[Assessment] = relationship(back_populates="scan_runs", lazy="joined")

    def __repr__(self) -> str:
        return f"<ScanRun id={self.id} scanner={self.scanner} status={self.status}>"


class Finding(Base, TimestampMixin):
    """Common Finding Format — every scanner normalises into this schema."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(f"severity IN {str(_FINDING_SEVERITY_VALUES)}", name="ck_findings_severity"),
        CheckConstraint(f"status IN {str(_FINDING_STATUS_VALUES)}", name="ck_findings_status"),
        Index("ix_findings_assessment_severity", "assessment_id", "severity"),
        Index("ix_findings_scanner_category", "scanner", "category"),
        Index("ix_findings_status_retest", "status", "retest_status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(20), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    affected_component: Mapped[str] = mapped_column(String(1024), default="", nullable=False)
    target: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    scanner: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    check_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    cvss_version: Mapped[str] = mapped_column(String(8), default="3.1", nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    severity_rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)

    reproduction: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    business_impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    remediation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    references: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)

    status: Mapped[str] = mapped_column(String(20), default="OPEN", nullable=False)
    authorized_target: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    retest_status: Mapped[str] = mapped_column(String(30), default="", nullable=False)
    retest_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    retested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="findings", lazy="joined")
    evidence_items: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity} check_id={self.check_id!r}>"


Index("ix_findings_fingerprint_unique_scope", Finding.assessment_id, Finding.fingerprint)
Index("ix_findings_severity_category", Finding.severity, Finding.category)


class Evidence(Base, TimestampMixin):
    """Pointer to an evidence file on disk (sanitised JSON)."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    kind: Mapped[str] = mapped_column(String(30), default="http_exchange", nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="evidence_items", lazy="joined")

    def __repr__(self) -> str:
        return f"<Evidence id={self.id} kind={self.kind}>"


class Report(Base, TimestampMixin):
    """Generated report artefact (PDF / JSON / Markdown / CSV)."""

    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint(f"format IN {str(_REPORT_FORMAT_VALUES)}", name="ck_reports_format"),
        Index("ix_reports_assessment_format", "assessment_id", "format"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True, nullable=False
    )
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(64), default="", nullable=False)

    assessment: Mapped[Assessment] = relationship(lazy="joined")

    def __repr__(self) -> str:
        return f"<Report id={self.id} format={self.format}>"


class AuditLog(Base, TimestampMixin):
    """Append-only audit trail."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_email: Mapped[str] = mapped_column(String(255), default="", index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    target: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action}>"


RETEST_ORIGINAL_EVIDENCE_KEY: str = "retest_original_evidence"

__all__ = [
    "Assessment",
    "AuditLog",
    "Evidence",
    "Finding",
    "Report",
    "RETEST_ORIGINAL_EVIDENCE_KEY",
    "ScanRun",
    "Target",
    "User",
]
