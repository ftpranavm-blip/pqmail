"""Production-grade serving for PQMail (waitress), with a safe fallback.

Why not just ``app.run()``?
===========================
Flask's built-in development server

* speaks HTTP/1.0, so the browser opens a brand-new connection for *every* file
  (page, stylesheet, scripts), and
* on Windows listens on IPv4 only. Browsers resolve ``localhost`` to the IPv6
  address ``::1`` first, wait for that to fail (about 200 ms) and only then try
  IPv4 - for every single connection. A page with four files can therefore sit
  blank for a second or more.

Waitress is a small, pure-Python, free WSGI server that keeps connections alive
(HTTP/1.1) and serves several requests in parallel threads. For loopback
addresses this module listens on **both** ``127.0.0.1`` and ``::1`` so that
``http://localhost:5000`` and ``http://127.0.0.1:5000`` are equally fast.

PQMail keeps unlocked keys in this process's memory, so it must stay a *single
process* (threads are fine, multiple worker processes are not).
"""
from __future__ import annotations

import socket

from app import config as cfg


def ipv6_loopback_available() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
        return True
    except OSError:
        return False


def listen_specs(host: str, port: int) -> list[str]:
    """Waitress ``listen`` entries for ``host``/``port`` (both loopback families for localhost)."""
    if cfg.is_loopback_host(host):
        specs = [f"127.0.0.1:{port}"]
        if ipv6_loopback_available():
            specs.append(f"[::1]:{port}")
        return specs
    if ":" in host:                       # a literal IPv6 address
        return [f"[{host}]:{port}"]
    return [f"{host}:{port}"]


def serve(app, host: str, port: int, threads: int = 8) -> None:
    """Run ``app`` until interrupted."""
    try:
        from waitress import create_server
    except ImportError:                   # pragma: no cover - waitress is in requirements.txt
        print("NOTE: 'waitress' is not installed - using Flask's slower development server.\n"
              "      Install it for much snappier pages:  pip install waitress")
        app.run(host=host, port=port, debug=False, threaded=True)
        return

    specs = listen_specs(host, port)
    try:
        server = create_server(app, listen=" ".join(specs), threads=threads, ident="PQMail")
    except OSError:
        if len(specs) == 1:
            raise
        # e.g. the IPv6 port is taken: fall back to IPv4 only
        specs = specs[:1]
        server = create_server(app, listen=specs[0], threads=threads, ident="PQMail")
    print("   Listening on: " + ", ".join("http://" + s for s in specs))
    print("   Press Ctrl+C to stop.")
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
