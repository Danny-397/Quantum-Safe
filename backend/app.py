"""QuantumSafe backend — Flask application factory.

Run locally:
    cd backend
    flask --app app run --debug      (or: python app.py)
"""

from __future__ import annotations

import os

from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from extensions import db, jwt, limiter, mail


def create_app(config_object: type = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    # Extensions
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    app.config["RATELIMIT_STORAGE_URI"] = app.config.get("RATELIMIT_STORAGE_URI", "memory://")

    # CORS restricted to the dashboard origin(s) only, for the API surface.
    CORS(
        app,
        resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}},
        supports_credentials=True,
    )

    # Blueprints
    from auth import auth_bp
    from api import api_bp
    from billing import billing_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(billing_bp)

    # Health check
    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "service": "quantumsafe-api"})

    @app.route("/")
    def index():
        return jsonify({"service": "QuantumSafe API", "version": "v1", "docs": "/api/v1"})

    # JSON error handlers
    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(429)
    def ratelimited(_e):
        return jsonify({"error": "Rate limit exceeded. Slow down and try again."}), 429

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Internal server error."}), 500

    # Create tables on startup (dev convenience; use migrations in production).
    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
