"""Application configuration, loaded from environment variables.

All secrets come from the environment (or a local .env in development). Nothing
sensitive is hardcoded.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _normalize_db_url(url: str) -> str:
    # Render/Heroku hand out postgres:// URLs; SQLAlchemy needs postgresql://.
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


# Plan definitions used across the API.
PLAN_FREE = "free"
PLAN_PRO = "pro"
PLAN_TEAM = "team"

FREE_MONTHLY_SCAN_LIMIT = 3


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = 60 * 60 * 24 * 7  # 7 days (seconds)

    SQLALCHEMY_DATABASE_URI = _normalize_db_url(
        os.environ.get("DATABASE_URL", "sqlite:///quantumsafe.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CORS: comma-separated list of allowed dashboard origins.
    FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
    CORS_ORIGINS = [o.strip() for o in FRONTEND_ORIGIN.split(",") if o.strip()]

    # Rate limiting backend (memory:// in dev; redis://... in prod).
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per hour")

    # Stripe
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    STRIPE_PRO_PRICE_ID = os.environ.get("STRIPE_PRO_PRICE_ID", "")
    STRIPE_TEAM_PRICE_ID = os.environ.get("STRIPE_TEAM_PRICE_ID", "")

    # Mail (email verification)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME or "no-reply@quantumsafe.dev")

    # Public URLs used to build links in emails / Stripe redirects.
    DASHBOARD_URL = os.environ.get("DASHBOARD_URL", FRONTEND_ORIGIN.split(",")[0])
    API_URL = os.environ.get("API_URL", "http://localhost:5000")
