"""Core REST API: scanning, scan history, findings, migration plan, exports,
and CLI API-key management.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import tempfile

from flask import Blueprint, Response, g, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import func

from auth import api_key_or_jwt, current_user, optional_user, send_email
from extensions import db, limiter
from models import Finding, Scan, User, generate_api_key
from quantumsafe.recommender import recommend
from quantumsafe.reporter import build_report, to_badge_svg, to_cbom, to_html, to_sarif
from quantumsafe.scanner import EXT_TO_LANG, scan_path
from scanner_service import persist_scan, scan_repo_url, scan_upload

DEMO_MAX_BYTES = 50_000

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


class _Unauthorized(Exception):
    """Raised when a valid JWT resolves to a missing user (e.g. deleted account)."""


@api_bp.errorhandler(_Unauthorized)
def _handle_unauthorized(_exc):
    return jsonify({"error": "Authentication required."}), 401


def _require_user() -> User:
    """Return the authenticated user, or raise -> JSON 401 (handles deleted accounts)."""
    user = current_user()
    if user is None:
        raise _Unauthorized()
    return user


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


@api_bp.route("/scan", methods=["POST"])
@limiter.limit("30 per hour")
@limiter.limit("10 per hour", exempt_when=lambda: optional_user() is not None)
def create_scan():
    """Run a scan for anyone. Signed-in callers get the result saved to their
    history; anonymous callers get the report back but nothing is stored.
    """
    user: User | None = optional_user()
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

    if user is None:
        # Anonymous: return the report; the browser holds it (nothing persisted).
        return jsonify({"report": report}), 201

    scan = persist_scan(user.id, report)
    _maybe_send_alert(user, scan, report)
    return jsonify({"scan_id": scan.id, "report": report}), 201


def _maybe_send_alert(user: User, scan, report: dict) -> None:
    """Email the user when a scan finds HIGH-risk findings (if they opted in)."""
    if not user.alert_on_high or report["summary"]["high"] == 0:
        return
    from flask import current_app
    s = report["summary"]
    dashboard = current_app.config["DASHBOARD_URL"]
    body = (
        f"QuantumSafe found {s['high']} HIGH-risk quantum vulnerabilities in your latest scan.\n\n"
        f"Target: {report['target']}\n"
        f"Quantum Risk Score: {report['risk_score']}/100 ({report['risk_band']})\n"
        f"HIGH: {s['high']}  MEDIUM: {s['medium']}  LOW: {s['low']}\n\n"
        f"View the full report and migration plan:\n"
        f"{dashboard}/scan.html?id={scan.id}\n"
    )
    send_email(
        f"QuantumSafe alert: {s['high']} HIGH-risk vulnerabilities found",
        user.email,
        body,
    )


def _sanitize_report(report: dict) -> dict:
    """Validate + clamp a CLI-supplied report to safe shapes/sizes before storing."""
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    findings_in = report.get("findings", [])
    if not isinstance(findings_in, list):
        raise ValueError("findings must be a list")
    summary = report.get("summary") or {}
    findings = []
    for f in findings_in[:10000]:  # cap to avoid DB bloat / abuse
        if not isinstance(f, dict):
            continue
        findings.append({
            "file_path": str(f.get("file_path", ""))[:1024],
            "line_number": int(f.get("line_number", 0) or 0),
            "algorithm": str(f.get("algorithm", ""))[:64],
            "risk_level": str(f.get("risk_level", "LOW"))[:10],
            "recommendation": str(f.get("recommendation", "")),
            "nist_reference": str(f.get("nist_reference", ""))[:255],
            "complexity": str(f.get("complexity", ""))[:10],
            "family": str(f.get("family", ""))[:32],
            "why": str(f.get("why", "")),
        })
    return {
        "target": str(report.get("target", "CLI scan"))[:1024],
        "risk_score": max(0, min(100, int(report.get("risk_score", 0) or 0))),
        "risk_band": str(report.get("risk_band", "Low"))[:20],
        "summary": {
            "high": int(summary.get("high", 0) or 0),
            "medium": int(summary.get("medium", 0) or 0),
            "low": int(summary.get("low", 0) or 0),
        },
        "findings": findings,
    }


@api_bp.route("/scan/import", methods=["POST"])
@limiter.limit("60 per hour")
@api_key_or_jwt
def import_scan():
    """Receive a report computed by the CLI and store it in the user's history.

    This is how `quantumsafe scan` (after `quantumsafe auth`) gets results into the
    dashboard: the CLI scans locally, then POSTs the finished report here.
    """
    user: User = g.current_user
    data = request.get_json(silent=True) or {}
    try:
        report = _sanitize_report(data.get("report", data))
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Invalid scan report payload."}), 400
    scan = persist_scan(user.id, report)
    _maybe_send_alert(user, scan, report)
    return jsonify({"scan_id": scan.id}), 201


@api_bp.route("/scans", methods=["GET"])
@jwt_required()
def list_scans():
    user = _require_user()
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
    user = _require_user()
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404
    return jsonify({"scan": scan.to_dict(include_findings=True)})


def _render_export(report: dict, fmt: str, filename_base: str):
    """Render a canonical report dict to a downloadable Response.

    Returns ``None`` for an unknown format so the caller can emit a 400. Missing
    optional fields are filled so both DB-backed and browser-held reports work.
    """
    report = dict(report)
    report.setdefault("tool", "quantumsafe")
    report.setdefault("version", "0.1.0")
    report.setdefault("target", "scan")
    report.setdefault("generated_at", "")
    report.setdefault("risk_message", "")
    summary = dict(report.get("summary") or {})
    summary.setdefault("high", 0)
    summary.setdefault("medium", 0)
    summary.setdefault("low", 0)
    summary.setdefault("total_findings", summary["high"] + summary["medium"] + summary["low"])
    report["summary"] = summary
    findings = report.get("findings", [])

    if fmt == "json":
        return jsonify(report)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["file_path", "line_number", "algorithm", "risk_level",
                         "recommendation", "nist_reference", "complexity"])
        for f in findings:
            writer.writerow([f.get("file_path", ""), f.get("line_number", 0),
                             f.get("algorithm", ""), f.get("risk_level", ""),
                             f.get("recommendation", ""), f.get("nist_reference", ""),
                             f.get("complexity", "")])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.csv"},
        )

    renderers = {
        "sarif": (to_sarif, "application/json", "sarif"),
        "cbom": (to_cbom, "application/json", "cbom.json"),
        "svg": (to_badge_svg, "image/svg+xml", "svg"),
        "html": (to_html, "text/html", "html"),
    }
    if fmt in renderers:
        render, mime, suffix = renderers[fmt]
        return Response(
            render(report), mimetype=mime,
            headers={"Content-Disposition": f"attachment; filename={filename_base}.{suffix}"},
        )
    return None


@api_bp.route("/scans/<int:scan_id>/export", methods=["GET"])
@jwt_required()
def export_scan(scan_id: int):
    user = _require_user()
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404

    fmt = request.args.get("format", "json").lower()
    if fmt == "json":
        # Signed-in JSON export keeps the richer scan shape (id, created_at, counts).
        return jsonify(scan.to_dict(include_findings=True))

    report = {
        "tool": "quantumsafe", "version": "0.1.0", "target": scan.repo_url,
        "generated_at": scan.created_at.isoformat() if scan.created_at else "",
        "risk_score": scan.risk_score, "risk_band": scan.risk_band,
        "risk_message": "", "summary": scan.to_dict()["summary"],
        "findings": [f.to_dict() for f in scan.findings],
    }
    resp = _render_export(report, fmt, f"scan_{scan_id}")
    if resp is None:
        return jsonify({"error": "format must be json, csv, html, sarif, cbom, or svg."}), 400
    return resp


@api_bp.route("/export", methods=["POST"])
@limiter.limit("60 per hour")
def export_from_report():
    """Stateless export for a browser-held (anonymous) report."""
    data = request.get_json(silent=True) or {}
    fmt = str(data.get("format", "json")).lower()
    try:
        report = _sanitize_report(data.get("report", data))
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Invalid scan report payload."}), 400
    resp = _render_export(report, fmt, "quantumsafe_scan")
    if resp is None:
        return jsonify({"error": "format must be json, csv, html, sarif, cbom, or svg."}), 400
    return resp


# --------------------------------------------------------------------------- #
# Overview / dashboard stats
# --------------------------------------------------------------------------- #


def _scans_this_month(user_id: int) -> int:
    start = dt.datetime.now(dt.timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    return Scan.query.filter(Scan.user_id == user_id, Scan.created_at >= start).count()


@api_bp.route("/overview", methods=["GET"])
@jwt_required()
def overview():
    user = _require_user()
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
    })


# --------------------------------------------------------------------------- #
# Migration plan
# --------------------------------------------------------------------------- #


def _build_migration_plan(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings into a HIGH/MEDIUM/LOW NIST migration plan.

    ``findings`` is a list of dicts with at least ``family``, ``algorithm``,
    ``risk_level``, ``file_path`` and ``line_number`` keys. Identical
    recommendations are aggregated with an occurrence count.
    """
    groups: dict[str, list[dict]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        family = f.get("family", "")
        algorithm = f.get("algorithm", "")
        level = f.get("risk_level", "LOW")
        if level not in groups:
            continue
        rec = recommend(family)
        key = (family, algorithm)
        existing = next((g for g in groups[level] if (g["family"], g["algorithm"]) == key), None)
        if existing:
            existing["occurrences"] += 1
        else:
            groups[level].append({
                "algorithm": algorithm,
                "family": family,
                "replace_with": rec.replacement,
                "nist_reference": rec.nist_reference,
                "complexity": rec.complexity,
                "detail": rec.detail,
                "occurrences": 1,
                "example": f"{f.get('file_path', '')}:{f.get('line_number', 0)}",
            })
    return groups


@api_bp.route("/scans/<int:scan_id>/migration", methods=["GET"])
@jwt_required()
def migration_plan(scan_id: int):
    user = _require_user()
    scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first()
    if scan is None:
        return jsonify({"error": "Scan not found."}), 404

    return jsonify({
        "scan_id": scan.id,
        "risk_score": scan.risk_score,
        "risk_band": scan.risk_band,
        "plan": _build_migration_plan([f.to_dict() for f in scan.findings]),
    })


@api_bp.route("/migration", methods=["POST"])
@limiter.limit("60 per hour")
def migration_plan_from_report():
    """Stateless migration plan for a browser-held (anonymous) report."""
    data = request.get_json(silent=True) or {}
    try:
        report = _sanitize_report(data.get("report", data))
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Invalid scan report payload."}), 400
    return jsonify({
        "risk_score": report["risk_score"],
        "risk_band": report["risk_band"],
        "plan": _build_migration_plan(report["findings"]),
    })


# --------------------------------------------------------------------------- #
# API key management (CLI)
# --------------------------------------------------------------------------- #


@api_bp.route("/demo-scan", methods=["POST"])
@limiter.limit("30 per hour")
def demo_scan():
    """Public, capped demo: runs the REAL scanner engine on a pasted snippet.

    No auth, nothing stored. This is the same engine behind the CLI/dashboard,
    limited to a single snippet so the landing-page demo is genuine, not a mock.
    """
    data = request.get_json(silent=True) or {}
    code = data.get("code") or ""
    if not isinstance(code, str) or not code.strip():
        return jsonify({"error": "Provide a 'code' string to scan."}), 400
    if len(code.encode("utf-8")) > DEMO_MAX_BYTES:
        return jsonify({"error": "Snippet too large for the demo (50 KB max). "
                                 "Use the CLI or sign up to scan whole repos."}), 413

    fname = os.path.basename(data.get("filename") or "snippet.py")  # no traversal
    if os.path.splitext(fname)[1].lower() not in EXT_TO_LANG:
        fname = "snippet.py"
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, fname), "w", encoding="utf-8") as fh:
            fh.write(code)
        findings = scan_path(tmp)
    return jsonify({"report": build_report(findings, "in-browser snippet")})


@api_bp.route("/user/data", methods=["GET"])
@jwt_required()
def export_user_data():
    """GDPR/CCPA right to access: download everything we hold about the user."""
    user = _require_user()
    scans = [s.to_dict(include_findings=True)
             for s in Scan.query.filter_by(user_id=user.id).all()]
    payload = {
        "account": user.to_dict(),
        "scans": scans,
        "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    return Response(
        json.dumps(payload, indent=2), mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=quantumsafe_my_data.json"},
    )


@api_bp.route("/user/account", methods=["DELETE"])
@jwt_required()
def delete_account():
    """GDPR/CCPA right to erasure: permanently delete the account + all data."""
    user = _require_user()
    db.session.delete(user)  # cascades to scans + findings
    db.session.commit()
    return jsonify({"message": "Your account and all associated data have been permanently deleted."})


@api_bp.route("/user/preferences", methods=["PUT"])
@jwt_required()
def update_preferences():
    user = _require_user()
    data = request.get_json(silent=True) or {}
    if "alert_on_high" in data:
        user.alert_on_high = bool(data["alert_on_high"])
    db.session.commit()
    return jsonify({"alert_on_high": user.alert_on_high})


@api_bp.route("/user/apikey", methods=["GET"])
@jwt_required()
def get_apikey():
    user = _require_user()
    return jsonify({
        "has_api_key": user.api_key_hash is not None,
        "api_key_prefix": user.api_key_prefix,
        "note": "The full key is shown only once, when generated or regenerated.",
    })


@api_bp.route("/user/apikey", methods=["POST"])
@jwt_required()
def regenerate_apikey():
    user = _require_user()
    full, key_hash, prefix = generate_api_key()
    user.api_key_hash = key_hash
    user.api_key_prefix = prefix
    db.session.commit()
    return jsonify({
        "api_key": full,
        "api_key_prefix": prefix,
        "message": "Store this key now — it will not be shown again.",
    }), 201
