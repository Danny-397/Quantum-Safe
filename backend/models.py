"""Database models and security helpers.

* Passwords are hashed with bcrypt.
* CLI API keys are shown to the user exactly once; only a SHA-256 hash and a
  short display prefix are stored, so a database leak never exposes usable keys.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets

import bcrypt

from config import PLAN_FREE
from extensions import db


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------- #
# Password helpers
# --------------------------------------------------------------------------- #


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# API key helpers
# --------------------------------------------------------------------------- #

API_KEY_PREFIX = "qs_live_"


def generate_api_key() -> tuple[str, str, str]:
    """Return (full_key, key_hash, display_prefix). Show full_key once only."""
    raw = secrets.token_urlsafe(32)
    full = f"{API_KEY_PREFIX}{raw}"
    return full, hash_api_key(full), full[: len(API_KEY_PREFIX) + 6]


def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    plan = db.Column(db.String(20), nullable=False, default=PLAN_FREE)

    api_key_hash = db.Column(db.String(64), unique=True, nullable=True, index=True)
    api_key_prefix = db.Column(db.String(32), nullable=True)

    stripe_customer_id = db.Column(db.String(255), nullable=True)

    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(64), nullable=True, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    scans = db.relationship("Scan", backref="user", lazy=True, cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "plan": self.plan,
            "email_verified": self.email_verified,
            "api_key_prefix": self.api_key_prefix,
            "has_api_key": self.api_key_hash is not None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    repo_url = db.Column(db.String(1024), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_band = db.Column(db.String(20), nullable=False, default="Low")
    high_count = db.Column(db.Integer, nullable=False, default=0)
    medium_count = db.Column(db.Integer, nullable=False, default=0)
    low_count = db.Column(db.Integer, nullable=False, default=0)
    findings_json = db.Column(db.Text, nullable=False, default="[]")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow, index=True)

    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")

    def to_dict(self, include_findings: bool = False) -> dict:
        data = {
            "id": self.id,
            "repo_url": self.repo_url,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "summary": {
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total_findings": self.high_count + self.medium_count + self.low_count,
            },
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_findings:
            data["findings"] = [f.to_dict() for f in self.findings]
        return data


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    file_path = db.Column(db.String(1024), nullable=False)
    line_number = db.Column(db.Integer, nullable=False, default=0)
    algorithm = db.Column(db.String(64), nullable=False)
    risk_level = db.Column(db.String(10), nullable=False)
    recommendation = db.Column(db.Text, nullable=False, default="")
    nist_reference = db.Column(db.String(255), nullable=False, default="")
    complexity = db.Column(db.String(10), nullable=False, default="")
    family = db.Column(db.String(32), nullable=False, default="")
    why = db.Column(db.Text, nullable=False, default="")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "algorithm": self.algorithm,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation,
            "nist_reference": self.nist_reference,
            "complexity": self.complexity,
            "family": self.family,
            "why": self.why,
        }
