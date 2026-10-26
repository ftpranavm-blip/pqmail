"""PQMail application package.

`create_app()` builds the Flask application, ensures the data directory
layout exists, provisions the demo users on first run and registers all
routes, error handlers and security headers.

Imports of the route blueprint are done lazily inside the factory to
avoid a circular import (routes themselves import this package's
submodules).
"""
from __future__ import annotations

import os
from datetime import timedelta

from flask import Flask, render_template, request, session

from app import config as cfg
from app.log import event


def create_app() -> Flask:
    # Lazy imports to break the app <-> routes circular dependency.
    from app import bootstrap, routes, security

    cfg.ensure_data_dirs()
    # Templates/static live at the project root (per the architecture spec),
    # so resolve them explicitly instead of relying on `__name__`.
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        template_folder=os.path.join(_root, "templates"),
        static_folder=os.path.join(_root, "static"),
    )
    # Session signing key: from PQMAIL_SECRET_KEY, otherwise a random key that
    # is generated once and persisted in the data directory, so browser
    # sessions survive restarts.
    app.config["SECRET_KEY"] = cfg.get_secret_key()
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_REQUEST_BYTES
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = cfg.COOKIE_SECURE
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(seconds=cfg.SESSION_LIFETIME_SECONDS)
    # Static files are fingerprinted (?v=<mtime>, see static_url), so browsers may cache
    # them for a long time: no re-validation round-trip for every page view.
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = timedelta(days=7)

    security.init_csrf(app)
    from app import i18n

    i18n.init_i18n(app)

    @app.template_global("static_url")
    def static_url(filename: str) -> str:
        """URL of a static file with a version stamp so a changed file is re-fetched."""
        from flask import url_for

        try:
            version = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
        except OSError:
            version = 0
        return url_for("static", filename=filename, v=version)

    @app.template_filter("filesize")
    def filesize(value) -> str:
        size = float(value or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} GB"

    app.register_blueprint(routes.bp)

    @app.context_processor
    def inject_globals():  # pragma: no cover - trivial glue
        user_email = session.get("user")
        pending_2fa = bool(session.get("twofa_pending"))
        if pending_2fa:
            user_email = None            # half-signed-in: show the logged-out chrome
        user_name, unread = None, 0
        if user_email:
            db = routes.database.get_db()
            row = db.get_user(user_email)
            user_name = row["display_name"] if row else user_email
            unread = db.count_envelopes(user_email, "inbox", unread_only=True)
        return {
            "nav_user_email": user_email,
            "nav_user_name": user_name,
            "nav_unread": unread,
            "nav_mode": session.get("mode", "demo"),
            "algos": cfg.algorithm_display_info(),
            "demo_enabled": cfg.DEMO_ENABLED,
            "demo_passphrase": cfg.DEMO_PASSPHRASE,
        }

    @app.after_request
    def security_headers(resp):  # pragma: no cover - trivial glue
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'none'",
        )
        # Decrypted mail must not linger in the browser cache or back/forward cache.
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Pragma"] = "no-cache"
        return resp

    @app.errorhandler(400)
    def bad_request(error):
        message = ("Your form expired or could not be verified. Go back, reload the page "
                   "and try again." if getattr(error, "description", "") == "csrf"
                   else "Bad request.")
        return render_template("error.html", code=400, message=message), 400

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return render_template("error.html", code=405, message="Method not allowed."), 405

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="The request was too large."), 413

    @app.errorhandler(500)
    def server_error(error):
        app.logger.exception("Unhandled server error (details are local only)")
        return (
            render_template(
                "error.html",
                code=500,
                message="Something went wrong. The incident was logged locally, no sensitive data is shown.",
            ),
            500,
        )

    bootstrap.ensure_demo_users()
    event("Application started")
    return app
