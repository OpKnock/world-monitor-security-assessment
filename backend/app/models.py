"""Normalized single database for the whole platform (spec §15)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(255), default="")
    first_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Assessment(Base, TimestampMixin):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    target: Mapped[str] = mapped_column(String(2048))
    source_path: Mapped[str] = mapped_column(String(2048), default="")  # filesystem scope for secrets/dep scanners
    modules: Mapped[list] = mapped_column(JSON, default=list)
    module_targets: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)  # queued|running|completed|failed
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship()
    scan_runs: Mapped[list["ScanRun"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")


class ScanRun(Base, TimestampMixin):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    scanner: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed|skipped
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    checks_total: Mapped[int] = mapped_column(Integer, default=0)
    checks_safe: Mapped[int] = mapped_column(Integer, default=0)
    raw_output_path: Mapped[str] = mapped_column(String(1024), default="")
    error: Mapped[str] = mapped_column(Text, default="")

    assessment: Mapped["Assessment"] = relationship(back_populates="scan_runs")


Index("ix_scan_runs_assessment_status", ScanRun.assessment_id, ScanRun.status)


class Finding(Base, TimestampMixin):
    """Common Finding Format — every scanner normalizes into this schema."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)

    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[Text] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), index=True)  # CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL
    category: Mapped[str] = mapped_column(String(40), index=True)
    affected_component: Mapped[str] = mapped_column(String(1024), default="")
    target: Mapped[str] = mapped_column(String(2048), default="")
    scanner: Mapped[str] = mapped_column(String(64), index=True)
    check_id: Mapped[str] = mapped_column(String(128))  # stable per-check identity
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # dedupe/retest key

    cvss_version: Mapped[str] = mapped_column(String(8), default="3.1")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(128), default="")
    severity_rationale: Mapped[Text] = mapped_column(Text, default="")

    reproduction: Mapped[list] = mapped_column(JSON, default=list)
    impact: Mapped[Text] = mapped_column(Text, default="")
    business_impact: Mapped[Text] = mapped_column(Text, default="")
    remediation: Mapped[Text] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)

    status: Mapped[str] = mapped_column(String(20), default="OPEN")  # OPEN|CONFIRMED|FALSE_POSITIVE|REMEDIATED|RETESTED
    authorized_target: Mapped[bool] = mapped_column(Boolean, default=True)

    retest_status: Mapped[str] = mapped_column(String(30), default="")  # NOT_RETESTED|FIXED|STILL_PRESENT
    retest_count: Mapped[int] = mapped_column(Integer, default=0)
    retested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    assessment: Mapped["Assessment"] = relationship(back_populates="findings")
    evidence_items: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


Index("ix_findings_fingerprint_unique_scope", Finding.assessment_id, Finding.fingerprint)


class Evidence(Base, TimestampMixin):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30), default="http_exchange")  # http_exchange|scanner_output|file_match
    path: Mapped[str] = mapped_column(String(1024))  # sanitized JSON file under EVIDENCE_DIR
    summary: Mapped[str] = mapped_column(Text, default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    finding: Mapped["Finding"] = relationship(back_populates="evidence_items")


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    format: Mapped[str] = mapped_column(String(10))  # pdf|json|md
    path: Mapped[str] = mapped_column(String(1024))
    generated_by: Mapped[str] = mapped_column(String(64), default="")

    assessment: Mapped["Assessment"] = relationship()


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_email: Mapped[str] = mapped_column(String(255), default="", index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(2048), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


RETEST_ORIGINAL_EVIDENCE_KEY = "retest_original_evidence"
