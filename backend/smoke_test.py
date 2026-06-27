"""End-to-end smoke test of the backend using Flask's test client.

Exercises the real code paths (no mocks): register -> login -> issue API key ->
scan an uploaded zip -> list/detail -> overview -> migration plan -> CSV export.
Uses an in-memory SQLite DB so it never touches a real database.

Run:  cd backend && python smoke_test.py
"""

import io
import os
import sys
import zipfile

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret"
os.environ["JWT_SECRET_KEY"] = "test-jwt"

from app import create_app  # noqa: E402
from config import Config  # noqa: E402


def _make_zip() -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/crypto.py", (
            "import hashlib\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "h = hashlib.md5(b'x').hexdigest()\n"
            "s = hashlib.sha256(b'x').hexdigest()\n"
        ))
        zf.writestr("src/app.js", "const k = crypto.generateKeyPairSync('rsa', {});\n")
    buf.seek(0)
    return buf


def main() -> int:
    app = create_app(Config)
    app.config["RATELIMIT_ENABLED"] = False  # don't rate-limit the test
    client = app.test_client()
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        ok = ok and cond

    print("register")
    r = client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "password123"})
    check("status 201", r.status_code == 201)
    token = r.get_json()["token"]
    check("got JWT", bool(token))
    auth = {"Authorization": f"Bearer {token}"}

    print("duplicate register rejected")
    r = client.post("/api/v1/auth/register", json={"email": "a@b.com", "password": "password123"})
    check("status 409", r.status_code == 409)

    print("login")
    r = client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "password123"})
    check("status 200", r.status_code == 200)
    check("wrong password rejected",
          client.post("/api/v1/auth/login", json={"email": "a@b.com", "password": "nope"}).status_code == 401)

    print("issue API key")
    r = client.post("/api/v1/user/apikey", headers=auth)
    check("status 201", r.status_code == 201)
    api_key = r.get_json()["api_key"]
    check("key prefixed", api_key.startswith("qs_live_"))

    print("scan upload (zip) via JWT")
    r = client.post("/api/v1/scan", headers=auth,
                    data={"file": (_make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    check("status 201", r.status_code == 201)
    report = r.get_json()["report"]
    check("score is computed > 0", report["risk_score"] > 0)
    check("found HIGH findings", report["summary"]["high"] >= 2)
    scan_id = r.get_json()["scan_id"]

    print("scan via API key (CLI path)")
    r = client.post("/api/v1/scan", headers={"X-API-Key": api_key},
                    data={"file": (_make_zip(), "code.zip")},
                    content_type="multipart/form-data")
    check("status 201", r.status_code == 201)

    print("list scans (paginated)")
    r = client.get("/api/v1/scans", headers=auth)
    check("status 200", r.status_code == 200)
    check("two scans listed", r.get_json()["total"] == 2)

    print("scan detail")
    r = client.get(f"/api/v1/scans/{scan_id}", headers=auth)
    check("status 200", r.status_code == 200)
    check("has findings", len(r.get_json()["scan"]["findings"]) > 0)

    print("overview")
    r = client.get("/api/v1/overview", headers=auth)
    check("status 200", r.status_code == 200)
    check("total_scans == 2", r.get_json()["total_scans"] == 2)

    print("migration plan")
    r = client.get(f"/api/v1/scans/{scan_id}/migration", headers=auth)
    check("status 200", r.status_code == 200)
    check("HIGH group populated", len(r.get_json()["plan"]["HIGH"]) > 0)

    print("CSV export")
    r = client.get(f"/api/v1/scans/{scan_id}/export?format=csv", headers=auth)
    check("status 200", r.status_code == 200)
    check("csv content", "algorithm" in r.get_data(as_text=True))

    print("auth required without token")
    check("401 unauthenticated", client.get("/api/v1/overview").status_code == 401)

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
