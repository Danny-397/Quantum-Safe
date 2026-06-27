"""Stripe billing: checkout sessions, webhook handling, and customer portal.

Works with Stripe test-mode keys out of the box. Plan upgrades happen only via
the verified webhook (the source of truth), never from the client redirect.
"""

from __future__ import annotations

import stripe
from flask import Blueprint, current_app, jsonify, request

from config import PLAN_FREE, PLAN_PRO, PLAN_TEAM
from extensions import db, limiter
from auth import current_user
from flask_jwt_extended import jwt_required
from models import User

billing_bp = Blueprint("billing", __name__, url_prefix="/api/v1/billing")


def _price_for_plan(plan: str) -> str | None:
    return {
        PLAN_PRO: current_app.config["STRIPE_PRO_PRICE_ID"],
        PLAN_TEAM: current_app.config["STRIPE_TEAM_PRICE_ID"],
    }.get(plan)


def _plan_for_price(price_id: str) -> str | None:
    mapping = {
        current_app.config["STRIPE_PRO_PRICE_ID"]: PLAN_PRO,
        current_app.config["STRIPE_TEAM_PRICE_ID"]: PLAN_TEAM,
    }
    return mapping.get(price_id)


def _init_stripe() -> bool:
    key = current_app.config.get("STRIPE_SECRET_KEY")
    if not key:
        return False
    stripe.api_key = key
    return True


@billing_bp.route("/checkout", methods=["POST"])
@limiter.limit("20 per hour")
@jwt_required()
def checkout():
    if not _init_stripe():
        return jsonify({"error": "Billing is not configured on this server."}), 503

    user = current_user()
    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "").lower()
    price_id = _price_for_plan(plan)
    if not price_id:
        return jsonify({"error": "plan must be 'pro' or 'team'."}), 400

    # Reuse or create a Stripe customer for this user.
    if not user.stripe_customer_id:
        customer = stripe.Customer.create(email=user.email, metadata={"user_id": user.id})
        user.stripe_customer_id = customer.id
        db.session.commit()

    dashboard = current_app.config["DASHBOARD_URL"]
    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=user.stripe_customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        client_reference_id=str(user.id),
        metadata={"user_id": user.id, "plan": plan},
        success_url=f"{dashboard}/dashboard.html?checkout=success",
        cancel_url=f"{dashboard}/dashboard.html?checkout=cancelled",
    )
    return jsonify({"url": session.url, "session_id": session.id})


@billing_bp.route("/portal", methods=["POST"])
@limiter.limit("20 per hour")
@jwt_required()
def portal():
    if not _init_stripe():
        return jsonify({"error": "Billing is not configured on this server."}), 503
    user = current_user()
    if not user.stripe_customer_id:
        return jsonify({"error": "No billing account found. Upgrade first."}), 400
    session = stripe.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=f"{current_app.config['DASHBOARD_URL']}/dashboard.html",
    )
    return jsonify({"url": session.url})


@billing_bp.route("/webhook", methods=["POST"])
def webhook():
    if not _init_stripe():
        return jsonify({"error": "Billing is not configured."}), 503

    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    secret = current_app.config["STRIPE_WEBHOOK_SECRET"]
    try:
        event = stripe.Webhook.construct_event(payload, sig, secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify({"error": "Invalid webhook signature."}), 400

    etype = event["type"]
    obj = event["data"]["object"]

    if etype == "checkout.session.completed":
        _handle_checkout_completed(obj)
    elif etype in ("customer.subscription.updated", "customer.subscription.created"):
        _handle_subscription_change(obj)
    elif etype == "customer.subscription.deleted":
        _handle_subscription_deleted(obj)

    return jsonify({"received": True})


def _handle_checkout_completed(session: dict) -> None:
    user = _resolve_user(session)
    if not user:
        return
    plan = (session.get("metadata") or {}).get("plan")
    if plan in (PLAN_PRO, PLAN_TEAM):
        user.plan = plan
        if session.get("customer"):
            user.stripe_customer_id = session["customer"]
        db.session.commit()


def _handle_subscription_change(sub: dict) -> None:
    user = _user_by_customer(sub.get("customer"))
    if not user:
        return
    try:
        price_id = sub["items"]["data"][0]["price"]["id"]
    except (KeyError, IndexError, TypeError):
        return
    plan = _plan_for_price(price_id)
    status = sub.get("status")
    if plan and status in ("active", "trialing"):
        user.plan = plan
        db.session.commit()


def _handle_subscription_deleted(sub: dict) -> None:
    user = _user_by_customer(sub.get("customer"))
    if user:
        user.plan = PLAN_FREE
        db.session.commit()


def _resolve_user(session: dict) -> User | None:
    ref = session.get("client_reference_id")
    if ref:
        user = db.session.get(User, int(ref))
        if user:
            return user
    return _user_by_customer(session.get("customer"))


def _user_by_customer(customer_id) -> User | None:
    if not customer_id:
        return None
    return User.query.filter_by(stripe_customer_id=customer_id).first()
