"""Authentication: registration, login, email verification, password reset,
and the decorators used to protect API routes.

* JWT (Flask-JWT-Extended) authenticates dashboard requests.
* API keys authenticate the CLI. ``api_key_or_jwt`` accepts either.
"""

from __future__ import annotations

import datetime as dt
import functools
import secrets

from flask import Blueprint, current_app, g, jsonify, request, url_for
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from extensions import db, limiter, mail
from models import (
    User,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_password,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")

RESET_SALT = "quantumsafe-password-reset"
RESET_MAX_AGE = 60 * 60  # 1 hour


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def _valid_email(email: str) -> bool:
    try:
        from email_validator import EmailNotValidError, validate_email
        validate_email(email, check_deliverability=False)
        return True
    except Exception:
        # Fallback if email_validator isn't installed.
        import re
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def send_email(subject: str, recipient: str, body: str) -> None:
    """Send an email, or log it to the console when SMTP isn't configured (dev)."""
    if not current_app.config.get("MAIL_SERVER"):
        current_app.logger.info("[email:dev] To: %s | %s\n%s", recipient, subject, body)
        return
    from flask_mail import Message
    msg = Message(subject=subject, recipients=[recipient], body=body)
    try:
        mail.send(msg)
    except Exception as exc:  # don't fail the request if email delivery hiccups
        current_app.logger.warning("Email send failed: %s", exc)


def current_user() -> User | None:
    """Resolve the User from a verified JWT identity."""
    identity = get_jwt_identity()
    if identity is None:
        return None
    return db.session.get(User, int(identity))


def optional_user() -> User | None:
    """Resolve a User from an API key or JWT if one is present; None if anonymous.

    Unlike ``api_key_or_jwt`` this never aborts the request — it lets a route serve
    both signed-in and logged-out callers (e.g. anonymous scanning).
    """
    api_key = request.headers.get("X-API-Key")
    auth_header = request.headers.get("Authorization", "")
    if not api_key and auth_header.startswith("Bearer qs_live_"):
        api_key = auth_header.split(" ", 1)[1]

    if api_key and api_key.startswith("qs_live_"):
        return User.query.filter_by(api_key_hash=hash_api_key(api_key)).first()

    try:
        verify_jwt_in_request(optional=True)
    except Exception:
        return None
    return current_user()


def api_key_or_jwt(fn):
    """Allow a route to be called with either a CLI API key or a dashboard JWT."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # 1) API key via X-API-Key header or Authorization: Bearer qs_live_...
        api_key = request.headers.get("X-API-Key")
        auth_header = request.headers.get("Authorization", "")
        if not api_key and auth_header.startswith("Bearer qs_live_"):
            api_key = auth_header.split(" ", 1)[1]

        if api_key and api_key.startswith("qs_live_"):
            user = User.query.filter_by(api_key_hash=hash_api_key(api_key)).first()
            if user is None:
                return jsonify({"error": "Invalid API key."}), 401
            g.current_user = user
            return fn(*args, **kwargs)

        # 2) Fall back to JWT (dashboard).
        try:
            verify_jwt_in_request()
        except Exception:
            return jsonify({"error": "Authentication required."}), 401
        user = current_user()
        if user is None:
            return jsonify({"error": "Authentication required."}), 401
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    accept_terms = bool(data.get("accept_terms"))

    if not _valid_email(email):
        return jsonify({"error": "A valid email is required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if not accept_terms:
        return jsonify({"error": "You must accept the Terms of Service and Privacy Policy."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with that email already exists."}), 409

    user = User(
        email=email,
        password_hash=hash_password(password),
        verification_token=secrets.token_urlsafe(24),
        terms_accepted_at=dt.datetime.now(dt.timezone.utc),
    )
    db.session.add(user)
    db.session.commit()

    verify_url = (
        f"{current_app.config['API_URL']}"
        f"{url_for('auth.verify_email')}?token={user.verification_token}"
    )
    send_email(
        "Verify your QuantumSafe account",
        email,
        f"Welcome to QuantumSafe!\n\nVerify your email:\n{verify_url}\n",
    )

    token = create_access_token(identity=str(user.id))
    return jsonify({
        "token": token,
        "user": user.to_dict(),
        "message": "Account created. Check your email to verify your address.",
    }), 201


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("20 per hour")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if user is None or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid email or password."}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({"token": token, "user": user.to_dict()})


@auth_bp.route("/verify", methods=["GET"])
def verify_email():
    token = request.args.get("token", "")
    user = User.query.filter_by(verification_token=token).first() if token else None
    if user is None:
        return jsonify({"error": "Invalid or expired verification token."}), 400
    user.email_verified = True
    user.verification_token = None
    db.session.commit()
    return jsonify({"message": "Email verified. You can now sign in to the dashboard."})


@auth_bp.route("/forgot", methods=["POST"])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    user = User.query.filter_by(email=email).first()
    # Always return 200 to avoid leaking which emails are registered.
    if user is not None:
        token = _serializer().dumps(user.id, salt=RESET_SALT)
        reset_url = f"{current_app.config['DASHBOARD_URL']}/login.html?reset={token}"
        send_email(
            "Reset your QuantumSafe password",
            email,
            f"Reset your password (valid for 1 hour):\n{reset_url}\n",
        )
    return jsonify({"message": "If that email exists, a reset link has been sent."})


@auth_bp.route("/reset", methods=["POST"])
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    password = data.get("password") or ""
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    try:
        user_id = _serializer().loads(token, salt=RESET_SALT, max_age=RESET_MAX_AGE)
    except SignatureExpired:
        return jsonify({"error": "Reset link has expired."}), 400
    except BadSignature:
        return jsonify({"error": "Invalid reset link."}), 400

    user = db.session.get(User, int(user_id))
    if user is None:
        return jsonify({"error": "Invalid reset link."}), 400
    user.password_hash = hash_password(password)
    db.session.commit()
    return jsonify({"message": "Password updated. You can now sign in."})


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    user = current_user()
    if user is None:
        return jsonify({"error": "Authentication required."}), 401
    return jsonify({"user": user.to_dict()})
