"""Regression tests for: language links on POST-result pages (used to 405), cached/versioned
static files, and the waitress server (IPv4 + IPv6 loopback, HTTP/1.1 keep-alive)."""
from __future__ import annotations

import http.client
import re
import threading

import pytest

from app import config as cfg
from app import server
from helpers import PASS, login, make_user, post


def lang_links(html: str) -> dict[str, str]:
    """{'en': '/x?lang=en', 'hi': ...} from the language switcher."""
    block = re.search(r'<span class="lang-switch".*?</span>', html, re.S)
    assert block, "language switcher missing"
    return {m.group(2): m.group(1).replace("&amp;", "&")
            for m in re.finditer(r'<a href="([^"]+)" lang="(\w+)"', block.group(0))}


def assert_switching_works(client, html):
    """Every language link must lead to a real page (redirects allowed) in that language."""
    links = lang_links(html)
    assert set(links) == {"en", "hi"}
    for code, href in links.items():
        resp = client.get(href, follow_redirects=True)
        assert resp.status_code == 200, (code, href, resp.status_code)
        assert f'<html lang="{code}">' in resp.get_data(as_text=True), (code, href)


def test_language_links_on_post_result_pages_do_not_405(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    pages = {
        "qkd result": post(client, "/qkd/run", {"bits": "256"}, page="/qkd"),
        "attack lab result": post(client, "/attack-lab/run", page="/attack-lab"),
        "failed compose": post(client, "/compose", {"to": "nobody@nowhere.test", "subject": "s", "body": "b"},
                               page="/compose"),
    }
    for name, resp in pages.items():
        assert resp.status_code in (200, 400), name
        assert_switching_works(client, resp.get_data(as_text=True))


def test_language_links_keep_the_query_string(client, demo_world):
    login(client, demo_world["alice"], demo_world["passphrase"])
    html = client.get("/inbox?filter=unread&page=1").get_data(as_text=True)
    links = lang_links(html)
    assert "filter=unread" in links["hi"] and "lang=hi" in links["hi"] and links["hi"].startswith("/inbox")
    assert client.get(links["hi"]).status_code == 200


def test_language_links_on_message_and_error_pages(client, demo_world, alice_keys):
    from app.services import mail_service

    mail_service.send_email(sender_email=demo_world["alice"], recipient_email=demo_world["bob"],
                            subject="s", body="b", sender_keys=alice_keys)
    from app import db as database

    mid = database.get_db().list_envelopes(demo_world["bob"], "inbox")[0]["message_id"]
    login(client, demo_world["bob"], demo_world["passphrase"])
    assert_switching_works(client, client.get(f"/message/{mid}").get_data(as_text=True))
    missing = client.get("/definitely-not-a-page")
    assert missing.status_code == 404
    assert_switching_works(client, missing.get_data(as_text=True))          # error pages keep a working switcher


def test_recovery_codes_page_has_no_language_switcher(client, demo_world):
    """The codes are shown once; a language link would navigate away and lose them."""
    from test_web_features import enable_2fa

    email, _ = make_user("lang2fa")
    login(client, email)
    _secret, codes, html = enable_2fa(client, email)
    assert codes and 'class="lang-switch"' not in html


def test_switching_language_while_2fa_pending(client, demo_world):
    from test_web_features import enable_2fa

    email, _ = make_user("lang2fa2")
    login(client, email)
    enable_2fa(client, email)
    post(client, "/logout", page="/dashboard")
    login(client, email)
    html = client.get("/login/2fa").get_data(as_text=True)
    assert_switching_works(client, html)
    assert client.get("/dashboard").status_code == 302                       # still not signed in


def test_static_files_are_versioned_and_cacheable(client):
    html = client.get("/login").get_data(as_text=True)
    for name in ("css/style.css", "js/app.js", "js/theme.js"):
        assert re.search(rf'/static/{re.escape(name)}\?v=\d+', html), name
    css = client.get(re.search(r'/static/css/style\.css\?v=\d+', html).group(0))
    cache = css.headers.get("Cache-Control", "")
    assert "max-age" in cache and "no-store" not in cache and int(re.search(r"max-age=(\d+)", cache).group(1)) >= 86400
    assert client.get("/login").headers["Cache-Control"] == "no-store"      # pages themselves are never cached


def test_no_gpu_heavy_blur_and_hindi_capable_fonts(client):
    css = client.get("/static/css/style.css").get_data(as_text=True)
    assert "backdrop-filter" not in css
    assert "Nirmala UI" in css and "Noto Sans Devanagari" in css


# ---------------------------------------------------------------------------
# waitress server
# ---------------------------------------------------------------------------
def test_listen_specs():
    assert server.listen_specs("127.0.0.1", 5000)[0] == "127.0.0.1:5000"
    assert "[::1]:5000" in server.listen_specs("localhost", 5000) or not server.ipv6_loopback_available()
    assert server.listen_specs("0.0.0.0", 8080) == ["0.0.0.0:8080"]
    assert server.listen_specs("::", 8080) == ["[::]:8080"]


@pytest.fixture()
def running_server(demo_world):
    from waitress import create_server

    from app import create_app, security, session_keys

    security.login_throttle.clear()
    session_keys.clear()
    app = create_app()
    listen = "127.0.0.1:0" + (" [::1]:0" if server.ipv6_loopback_available() else "")
    srv = create_server(app, listen=listen, threads=4)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    yield srv.effective_listen
    srv.close()
    thread.join(timeout=5)


def test_server_answers_on_ipv4_and_ipv6_with_keep_alive(running_server):
    assert running_server
    for host, port in running_server:
        conn_cls = http.client.HTTPConnection
        conn = conn_cls(host.strip("[]"), port, timeout=5)
        try:
            for _ in range(3):                               # three requests over ONE connection
                conn.request("GET", "/login")
                resp = conn.getresponse()
                body = resp.read()
                assert resp.status == 200 and b"PQMail" in body
                assert resp.version == 11                    # HTTP/1.1 -> keep-alive is possible
            conn.request("GET", "/static/css/style.css")
            css = conn.getresponse()
            css.read()
            assert css.status == 200 and "max-age" in css.getheader("Cache-Control", "")
        finally:
            conn.close()


def test_server_serves_a_full_login_flow(running_server):
    host, port = running_server[0]
    conn = http.client.HTTPConnection(host.strip("[]"), port, timeout=10)
    try:
        conn.request("GET", "/login")
        page = conn.getresponse()
        html = page.read().decode()
        cookie = page.getheader("Set-Cookie", "").split(";")[0]
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        from urllib.parse import urlencode

        body = urlencode({"email": "alice@pqmail.local", "passphrase": cfg.DEMO_PASSPHRASE, "csrf_token": token})
        conn.request("POST", "/login", body=body, headers={
            "Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 302 and resp.getheader("Location", "").endswith("/dashboard")
    finally:
        conn.close()


def test_serve_falls_back_to_ipv4_when_ipv6_port_is_taken(monkeypatch):
    """create_server raising for the dual-stack spec must retry with IPv4 only."""
    import waitress

    calls = []

    class FakeServer:
        def run(self):
            return None

        def close(self):
            return None

    def fake_create(app, listen, **kw):
        calls.append(listen)
        if len(calls) == 1:
            raise OSError("address already in use")
        return FakeServer()

    monkeypatch.setattr(waitress, "create_server", fake_create)
    monkeypatch.setattr(server, "ipv6_loopback_available", lambda: True)
    server.serve(object(), "127.0.0.1", 5999)
    assert calls == ["127.0.0.1:5999 [::1]:5999", "127.0.0.1:5999"]


def test_serve_uses_flask_dev_server_when_waitress_is_missing(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_waitress(name, *args, **kwargs):
        if name == "waitress":
            raise ImportError("simulated")
        return real_import(name, *args, **kwargs)

    ran = {}

    class FakeApp:
        def run(self, **kw):
            ran.update(kw)

    monkeypatch.setattr(builtins, "__import__", no_waitress)
    server.serve(FakeApp(), "127.0.0.1", 5998)
    assert ran == {"host": "127.0.0.1", "port": 5998, "debug": False, "threaded": True}


def test_non_loopback_binding_is_still_refused_with_demo_mode(monkeypatch):
    monkeypatch.setattr(cfg, "DEMO_ENABLED", True)
    assert cfg.check_safe_binding("0.0.0.0")
    assert PASS                                                   # (helper import kept for clarity)
