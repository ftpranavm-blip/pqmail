"""PQMail — Quantum-Secure Email Client (educational prototype).

Run with:

    python app.py

and open http://127.0.0.1:5000 in your browser.
"""
from __future__ import annotations

import logging
import sys

from app import create_app
from app.config import check_safe_binding, flask_host, flask_port

logging.basicConfig(level=logging.INFO)


def main() -> None:
    host, port = flask_host(), flask_port()
    problem = check_safe_binding(host)
    if problem:
        print(f"ERROR: {problem}", file=sys.stderr)
        raise SystemExit(2)
    app = create_app()
    print("=" * 64)
    print(" PQMail - Quantum-Secure Email Client (educational prototype)")
    print(f"   Open:  http://{host}:{port}")
    print("   Demo users are created on first start (see the login page).")
    print("   The QKD page is an EDUCATIONAL SIMULATION, not real quantum hardware.")
    print("=" * 64)
    # waitress (HTTP/1.1 keep-alive, IPv4 + IPv6 loopback); falls back to Flask's dev
    # server if it is missing. debug is never enabled: no interactive debugger.
    from app.server import serve

    serve(app, host, port)


if __name__ == "__main__":
    main()
