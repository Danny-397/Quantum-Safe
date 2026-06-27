"""Core REST API: scanning, scan history, findings, migration plan, exports,
and CLI API-key management.
"""

from __future__ import annotations

import csv
import datetime as dt
import io

from flask import Blueprint, Response, g, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func

from auth import api_key_or_jwt, current_user
from config import FREE_MONTHLY_SCAN_LIMIT, PLAN_FREE
from extensions import db, limiter
from models import Finding, Scan, User, generate_api_key
from quantumsafe.recommender import recommend
from quantumsafe.reporter import to_html
from scanner_service import persist_scan, scan_repo_url, scan_upload

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


# --------------------------------------------------------------------------- #
# Plan enforcement
# --------------------------------------------------------------------------- #


def _scans_this_month(user_id: int) -> int:
    start = dt.datetime.now(dt.timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    return Scan.query.filter(Scan.user_id == user_id, Scan.created_at >= start).count()


def _enforce_scan_limit(user: User) -> tuple[bool, str]:
    if user.plan == PLAN_FREE:
        used = _scans_this_month(user.id)
        if used >= FREE_MONTHLY_SCAN_LIMIT:
            return False, (
                f"Free plan is limited to {FREE_MONTHLY_SCAN_LIMIT} scans per month. "
                "Upgrade to Pro for unlimited scans."
            )
    return True, ""


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


@api_bp.route("/scan", methods=["POST"])
@limiter.limit("30 per hour")
@api_key_or_jwt
def create_scan():
    user: User = g.current_user

    allowed, msg = _enforce_scan_limit(user)
    if not allowed:
        return jsonify({"error": msg}), 402  # Payment Required

    try:
        if "file" in request.files:
            report = scan_upload(request.files["file"])
        else:
            data = request.get_json(silent=True) or {}
            repo_url = (data.get("repo_url") or request.form.get("repo_url") or "").strip()
            if not repo_url:
                return jsonify({"error": "Provide a repo_url or a file upload."}), 400
            report = scan_repo_url(repo_url)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 502

    scan = persist_scan(user.id, report)
    return jsonify({"scan_id": scan.id, "report": report}), 201


@api_bp.route("/scans", methods=["GET"])
@jwt_required()
def list_scans():
    user = current_user()
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))

    pagination = (
        Scan.query.filter_by(user_id=user.id)
        .order_by(Scan.created_at.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
    return jsonify({
        "scans": [s.to_dict() for s in pagination.items],
        "page": page,
        "per_page": per_page,
        "total": pagination.total,
        "pages": pagination.pages,
    })


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id: int):
    user = current_user()
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify({"scan": scan.to_dict(include_findings=True)})


@api_bp.route("/scans/<int:scan_id>/export", methods=["GET"])
@jwt_required()
def export_scan(scan_id: int):
    user = current_user()
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404

    fmt = request.args.get("format", "json").lower()
    findings = [f.to_dict() for f in scan.findings]

    if fmt == "json":
        return jsonify(scan.to_dict(include_findings=True))

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["file_path", "line_number", "algorithm", "risk_level",
                         "recommendation", "nist_reference", "complexity"])
        for f in findings:
            writer.writerow([f["file_path"], f["line_number"], f["algorithm"],
                             f["risk_level"], f["recommendation"],
                             f["nist_reference"], f["complexity"]])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"},
        )

    if fmt == "html":
        report = {
            "tool": "quantumsafe", "version": "0.1.0", "target": scan.repo_url,
            "generated_at": scan.created_at.isoformat() if scan.created_at else "",
            "risk_score": scan.risk_score, "risk_band": scan.risk_band,
            "risk_message": "", "summary": scan.to_dict()["summary"], "findings": findings,
        }
        return Response(
            to_html(report), mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.html"},
        )

    return jsonify({"error": "format must be json, csv, or html."}), 400


# --------------------------------------------------------------------------- #
# Overview / dashboard stats
# --------------------------------------------------------------------------- #


@api_bp.route("/overview", methods=["GET"])
@jwt_required()
def overview():
    user = current_user()
    scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).all()

    totals = db.session.query(
        func.coalesce(func.sum(Scan.high_count), 0),
        func.coalesce(func.sum(Scan.medium_count), 0),
        func.coalesce(func.sum(Scan.low_count), 0),
    ).filter(Scan.user_id == user.id).first()

    latest = scans[0] if scans else None
    trend = [
        {"date": s.created_at.isoformat() if s.created_at else None, "score": s.risk_score}
        for s in reversed(scans[:30])
    ]
    return jsonify({
        "latest_score": latest.risk_score if latest else 0,
        "latest_band": latest.risk_band if latest else "Low",
        "total_scans": len(scans),
        "findings": {"high": int(totals[0]), "medium": int(totals[1]), "low": int(totals[2])},
        "recent_scans": [s.to_dict() for s in scans[:5]],
        "trend": trend,
        "scans_this_month": _scans_this_month(user.id),
        "plan": user.plan,
    })


# --------------------------------------------------------------------------- #
# Migration plan
# --------------------------------------------------------------------------- #


@api_bp.route("/scans/<int:scan_id>/migration", methods=["GET"])
@jwt_required()
def migration_plan(scan_id: int):
    user = current_user()
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404

    groups: dict[str, list[dict]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
    seen: set[tuple] = set()
    for f in scan.findings:
        rec = recommend(f.family)
        key = (f.family, f.algorithm)
        item = {
            "algorithm": f.algorithm,
            "family": f.family,
            "replace_with": rec.replacement,
            "nist_reference": rec.nist_reference,
            "complexity": rec.complexity,
            "detail": rec.detail,
            "occurrences": 1,
            "example": f"{f.file_path}:{f.line_number}",
        }
        # Aggregate identical recommendations, counting occurrences.
        existing = next((g for g in groups[f.risk_level] if (g["family"], g["algorithm"]) == key), None)
        if existing:
            existing["occurrences"] += 1
        else:
            groups[f.risk_level].append(item)
        seen.add(key)

    return jsonify({
        "scan_id": scan.id,
        "risk_score": scan.risk_score,
        "risk_band": scan.risk_band,
        "plan": groups,
    })


# --------------------------------------------------------------------------- #
# API key management (CLI)
# --------------------------------------------------------------------------- #


@api_bp.route("/user/apikey", methods=["GET"])
@jwt_required()
def get_apikey():
    user = current_user()
    return jsonify({
        "has_api_key": user.api_key_hash is not None,
        "api_key_prefix": user.api_key_prefix,
        "note": "The full key is shown only once, when generated or regenerated.",
    })


@api_bp.route("/user/apikey", methods=["POST"])
@jwt_required()
def regenerate_apikey():
    user = current_user()
    full, key_hash, prefix = generate_api_key()
    user.api_key_hash = key_hash
    user.api_key_prefix = prefix
    db.session.commit()
    return jsonify({
        "api_key": full,
        "api_key_prefix": prefix,
        "message": "Store this key now — it will not be shown again.",
    }), 201
