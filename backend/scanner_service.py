"""Runs the QuantumSafe scanner for the backend and persists results.

This imports the same ``quantumsafe`` package that powers the CLI (installed via
``pip install -e .`` from the repo root), so the dashboard and CLI produce
identical findings — there is exactly one detection engine.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import zipfile

from werkzeug.utils import secure_filename

from quantumsafe.reporter import build_report
from quantumsafe.scanner import scan_path, scan_repo

from extensions import db
from models import Finding, Scan

_ALLOWED_UPLOAD_EXT = {".zip"}
_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB


def scan_repo_url(url: str) -> dict:
    """Clone + scan a GitHub repo, returning the canonical report dict.

    URL validation / sanitization happens inside quantumsafe.scanner.scan_repo
    (https-only github.com, no traversal), which raises ValueError on bad input.
    """
    findings = scan_repo(url)
    return build_report(findings, url)


def scan_upload(file_storage) -> dict:
    """Scan an uploaded .zip archive of a codebase, then clean up."""
    filename = secure_filename(file_storage.filename or "")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in _ALLOWED_UPLOAD_EXT:
        raise ValueError("Only .zip uploads are supported.")

    tmp_dir = tempfile.mkdtemp(prefix="quantumsafe_upload_")
    try:
        zip_path = os.path.join(tmp_dir, filename)
        file_storage.save(zip_path)
        if os.path.getsize(zip_path) > _MAX_UPLOAD_BYTES:
            raise ValueError("Upload exceeds the 25 MB limit.")

        extract_dir = os.path.join(tmp_dir, "src")
        os.makedirs(extract_dir, exist_ok=True)
        _safe_extract(zip_path, extract_dir)

        findings = scan_path(extract_dir)
        return build_report(findings, filename)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _safe_extract(zip_path: str, dest: str) -> None:
    """Extract a zip, refusing any entry that would escape the destination."""
    dest_abs = os.path.abspath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = os.path.abspath(os.path.join(dest, member))
            if not target.startswith(dest_abs + os.sep) and target != dest_abs:
                raise ValueError("Unsafe path detected in archive (zip slip).")
        zf.extractall(dest)


def persist_scan(user_id: int, report: dict) -> Scan:
    """Save a report (and its findings) to the database and return the Scan row."""
    s = report["summary"]
    scan = Scan(
        user_id=user_id,
        repo_url=report["target"],
        risk_score=report["risk_score"],
        risk_band=report["risk_band"],
        high_count=s["high"],
        medium_count=s["medium"],
        low_count=s["low"],
        findings_json=_dump_findings(report["findings"]),
    )
    db.session.add(scan)
    db.session.flush()  # get scan.id

    for f in report["findings"]:
        db.session.add(Finding(
            scan_id=scan.id,
            file_path=f["file_path"],
            line_number=f["line_number"],
            algorithm=f["algorithm"],
            risk_level=f["risk_level"],
            recommendation=f["recommendation"],
            nist_reference=f["nist_reference"],
            complexity=f["complexity"],
            family=f["family"],
            why=f["why"],
        ))
    db.session.commit()
    return scan


def _dump_findings(findings: list[dict]) -> str:
    import json
    return json.dumps(findings)
