"""End-to-end API tests against the real Flask app (in-memory DB)."""

import io
import zipfile

import pytest


def make_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.py",
                    "import hashlib\n"
                    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                    "h = hashlib.md5(b'x')\n")
    buf.seek(0)
    return buf


# ---- auth ----------------------------------------------------------------- #

def test_register_returns_token(client):
    r = client.post("/api/v1/auth/register",
                    json={"email": "a@b.com", "password": "password123", "accept_terms": True})
    assert r.status_code == 201
    assert r.get_json()["token"]
    assert r.get_json()["user"]["terms_accepted_at"]  # consent recorded


def test_register_rejects_short_password(client):
    r = client.post("/api/v1/auth/register",
                    json={"email": "a@b.com", "password": "short", "accept_terms": True})
    assert r.status_code == 400


def test_register_requires_consent(client):
    r = client.post("/api/v1/auth/register",
                    json={"email": "noconsent@b.com", "password": "password123"})
    assert r.status_code == 400


def test_register_rejects_duplicate(client):
    j = {"email": "dup@b.com", "password": "password123", "accept_terms": True}
    client.post("/api/v1/auth/register", json=j)
    assert client.post("/api/v1/auth/register", json=j).status_code == 409


def test_login_and_bad_login(client):
    client.post("/api/v1/auth/register",
                json={"email": "l@b.com", "password": "password123", "accept_terms": True})
    assert client.post("/api/v1/auth/login", json={"email": "l@b.com", "password": "password123"}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": "l@b.com", "password": "nope"}).status_code == 401


def test_protected_endpoint_requires_auth(client):
    assert client.get("/api/v1/overview").status_code == 401


# ---- api keys ------------------------------------------------------------- #

def test_apikey_generation(auth_client):
    client, headers = auth_client
    r = client.post("/api/v1/user/apikey", headers=headers)
    assert r.status_code == 201
    assert r.get_json()["api_key"].startswith("qs_live_")


# ---- scanning ------------------------------------------------------------- #

def test_scan_upload_and_persist(auth_client):
    client, headers = auth_client
    r = client.post("/api/v1/scan", headers=headers,
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 201
    report = r.get_json()["report"]
    assert report["risk_score"] > 0
    assert report["summary"]["high"] >= 2


def test_scan_via_api_key(auth_client):
    client, headers = auth_client
    key = client.post("/api/v1/user/apikey", headers=headers).get_json()["api_key"]
    r = client.post("/api/v1/scan", headers={"X-API-Key": key},
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 201


def test_list_detail_overview_migration(auth_client):
    client, headers = auth_client
    sid = client.post("/api/v1/scan", headers=headers,
                      data={"file": (make_zip(), "code.zip")},
                      content_type="multipart/form-data").get_json()["scan_id"]

    assert client.get("/api/v1/scans", headers=headers).get_json()["total"] == 1
    detail = client.get(f"/api/v1/scans/{sid}", headers=headers).get_json()["scan"]
    assert len(detail["findings"]) > 0
    assert client.get("/api/v1/overview", headers=headers).get_json()["total_scans"] == 1
    mig = client.get(f"/api/v1/scans/{sid}/migration", headers=headers).get_json()
    assert len(mig["plan"]["HIGH"]) > 0


@pytest.mark.parametrize("fmt,needle", [
    ("csv", "file_path"),
    ("html", "<!DOCTYPE html>"),
])
def test_exports(auth_client, fmt, needle):
    client, headers = auth_client
    sid = client.post("/api/v1/scan", headers=headers,
                      data={"file": (make_zip(), "code.zip")},
                      content_type="multipart/form-data").get_json()["scan_id"]
    r = client.get(f"/api/v1/scans/{sid}/export?format={fmt}", headers=headers)
    assert r.status_code == 200
    assert needle in r.get_data(as_text=True)


def test_scans_are_unlimited(auth_client):
    client, headers = auth_client
    # No paywall: many scans all succeed.
    for _ in range(5):
        assert client.post("/api/v1/scan", headers=headers,
                           data={"file": (make_zip(), "code.zip")},
                           content_type="multipart/form-data").status_code == 201


def test_cli_import_scan_appears_in_dashboard(auth_client):
    client, headers = auth_client
    key = client.post("/api/v1/user/apikey", headers=headers).get_json()["api_key"]
    report = {
        "target": "./local-project", "risk_score": 45, "risk_band": "Medium",
        "summary": {"high": 3, "medium": 0, "low": 0},
        "findings": [{"file_path": "a.py", "line_number": 2, "algorithm": "MD5",
                      "risk_level": "HIGH", "recommendation": "SHA-3",
                      "nist_reference": "FIPS 202", "complexity": "Low",
                      "family": "md5", "why": "broken"}],
    }
    r = client.post("/api/v1/scan/import", headers={"X-API-Key": key}, json={"report": report})
    assert r.status_code == 201
    sid = r.get_json()["scan_id"]
    # It now shows up in the user's dashboard history.
    assert client.get("/api/v1/scans", headers=headers).get_json()["total"] == 1
    detail = client.get(f"/api/v1/scans/{sid}", headers=headers).get_json()["scan"]
    assert detail["risk_score"] == 45
    assert detail["findings"][0]["algorithm"] == "MD5"


def test_import_scan_rejects_garbage(auth_client):
    client, headers = auth_client
    key = client.post("/api/v1/user/apikey", headers=headers).get_json()["api_key"]
    r = client.post("/api/v1/scan/import", headers={"X-API-Key": key},
                    json={"report": {"findings": "not-a-list"}})
    assert r.status_code == 400


def test_import_scan_requires_auth(client):
    r = client.post("/api/v1/scan/import", json={"report": {"findings": []}})
    assert r.status_code == 401


def test_demo_scan_runs_real_engine(client):
    r = client.post("/api/v1/demo-scan",
                    json={"code": "import hashlib\nh = hashlib.md5(b'x')\n", "filename": "x.py"})
    assert r.status_code == 200
    report = r.get_json()["report"]
    assert report["summary"]["high"] >= 1  # real engine flagged MD5
    assert any(f["algorithm"] == "MD5" for f in report["findings"])


def test_demo_scan_rejects_empty_and_huge(client):
    assert client.post("/api/v1/demo-scan", json={"code": "  "}).status_code == 400
    assert client.post("/api/v1/demo-scan", json={"code": "x" * 60000}).status_code == 413


# ---- anonymous (no-account) flow ------------------------------------------ #

def _anon_report(client):
    """Run an anonymous zip scan and return its report (browser-held payload)."""
    return client.post("/api/v1/scan",
                       data={"file": (make_zip(), "code.zip")},
                       content_type="multipart/form-data").get_json()["report"]


def test_anonymous_scan_returns_report_not_persisted(client, app):
    r = client.post("/api/v1/scan",
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 201
    body = r.get_json()
    assert "report" in body
    assert "scan_id" not in body            # anonymous scans are never saved
    assert body["report"]["summary"]["high"] >= 2
    with app.app_context():
        from models import Scan
        assert Scan.query.count() == 0      # nothing written to the database


def test_authenticated_scan_still_persists(auth_client):
    client, headers = auth_client
    r = client.post("/api/v1/scan", headers=headers,
                    data={"file": (make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    assert r.status_code == 201
    assert r.get_json()["scan_id"]
    assert client.get("/api/v1/overview", headers=headers).get_json()["total_scans"] == 1


def test_anonymous_migration_from_report(client):
    r = client.post("/api/v1/migration", json={"report": _anon_report(client)})
    assert r.status_code == 200
    assert len(r.get_json()["plan"]["HIGH"]) > 0   # RSA/MD5 land in HIGH


def test_anonymous_export_sarif(client):
    r = client.post("/api/v1/export", json={"report": _anon_report(client), "format": "sarif"})
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert '"version": "2.1.0"' in text and "runs" in text


def test_anonymous_export_rejects_bad_format(client):
    r = client.post("/api/v1/export", json={"report": _anon_report(client), "format": "docx"})
    assert r.status_code == 400


def test_save_after_login_persists_held_report(client):
    """Anonymous scan → register → import the held report → it's in history."""
    import uuid
    report = _anon_report(client)
    email = f"save-{uuid.uuid4().hex[:8]}@test.com"
    token = client.post("/api/v1/auth/register",
                        json={"email": email, "password": "password123", "accept_terms": True}
                        ).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/v1/scan/import", headers=headers, json={"report": report})
    assert r.status_code == 201
    assert client.get("/api/v1/overview", headers=headers).get_json()["total_scans"] == 1


def test_export_user_data(auth_client):
    client, headers = auth_client
    r = client.get("/api/v1/user/data", headers=headers)
    assert r.status_code == 200
    data = r.get_json()
    assert "account" in data and "scans" in data


def test_delete_account_removes_data(auth_client):
    client, headers = auth_client
    # create a scan, then delete the account
    client.post("/api/v1/scan", headers=headers,
                data={"file": (make_zip(), "code.zip")}, content_type="multipart/form-data")
    assert client.delete("/api/v1/user/account", headers=headers).status_code == 200
    # token now resolves to a deleted user -> unauthorized
    assert client.get("/api/v1/overview", headers=headers).status_code == 401
