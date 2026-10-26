"""The Hindi catalog must cover every translatable string and keep placeholders intact."""
from __future__ import annotations

import ast
import pathlib
import re

import pytest
from jinja2 import Environment, nodes

from app.translations.hi import CATALOG
from helpers import login

ROOT = pathlib.Path(__file__).resolve().parent.parent
_PLACEHOLDER = re.compile(r"%\((\w+)\)[sdf.\d]*[sdf]?")


def _source_strings() -> set[str]:
    found: set[str] = set()
    env = Environment()
    for f in (ROOT / "templates").glob("*.html"):
        for call in env.parse(f.read_text(encoding="utf-8")).find_all(nodes.Call):
            if isinstance(call.node, nodes.Name) and call.node.name == "_" and call.args \
                    and isinstance(call.args[0], nodes.Const) and isinstance(call.args[0].value, str):
                found.add(call.args[0].value)
    for f in (ROOT / "app").rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_" \
                    and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str):
                found.add(node.args[0].value)
    return found


def test_every_translatable_string_has_a_hindi_translation():
    missing = sorted(_source_strings() - set(CATALOG))
    assert not missing, f"{len(missing)} strings missing from app/translations/hi.py: {missing[:8]}"


def test_catalog_has_no_stale_entries():
    stale = sorted(set(CATALOG) - _source_strings())
    assert not stale, f"stale catalog keys (no longer used): {stale[:8]}"


def test_placeholders_and_percent_signs_are_preserved():
    for english, hindi in CATALOG.items():
        assert sorted(_PLACEHOLDER.findall(english)) == sorted(_PLACEHOLDER.findall(hindi)), english
        assert english.count("%%") == hindi.count("%%"), english
        # a lone % that is not part of a placeholder or %% would break %-formatting
        cleaned = _PLACEHOLDER.sub("", hindi).replace("%%", "")
        assert "%" not in cleaned, english
        assert hindi.strip(), english


def test_translations_are_actually_hindi_where_expected():
    devanagari = re.compile(r"[\u0900-\u097F]")
    untranslated = [k for k, v in CATALOG.items() if not devanagari.search(v)]
    assert not untranslated, untranslated[:5]


@pytest.mark.parametrize("path,needle", [
    ("/login?lang=hi", "साइन इन"),
    ("/register?lang=hi", "अपनी क्वांटम-सुरक्षित पहचान बनाएँ"),
    ("/?lang=hi", "ऐसा ईमेल जो निजी रहता है"),
])
def test_public_pages_render_in_hindi(client, path, needle):
    html = client.get(path).get_data(as_text=True)
    assert needle in html and 'lang="hi"' in html


def test_signed_in_pages_render_in_hindi_without_errors(client, demo_world):
    client.get("/login?lang=hi")
    login(client, demo_world["alice"], demo_world["passphrase"])
    expectations = {
        "/dashboard": "डैशबोर्ड", "/inbox": "इनबॉक्स", "/sent": "भेजे गए", "/compose": "एन्क्रिप्टेड ईमेल लिखें",
        "/trash": "ट्रैश", "/contacts": "संपर्क", "/keys": "आपकी क्वांटम-सुरक्षित पहचान",
        "/settings": "सेटिंग्स", "/qkd": "शैक्षिक QKD सिमुलेशन", "/transparency": "कुंजी पारदर्शिता लॉग",
        "/attack-lab": "हमला प्रयोगशाला", "/benchmarks": "जीवंत बेंचमार्क", "/settings/2fa": "टू-फ़ैक्टर प्रमाणीकरण",
    }
    for path, needle in expectations.items():
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert needle in resp.get_data(as_text=True), path


def test_flash_messages_are_translated(client, demo_world):
    client.get("/login?lang=hi")
    resp = client.post("/login", data={"email": demo_world["alice"], "passphrase": "wrong-passphrase-x",
                                       "csrf_token": __import__("helpers").token(client)}, follow_redirects=True)
    assert "लॉगिन विफल" in resp.get_data(as_text=True)


def test_language_falls_back_to_accept_language_header(client):
    html = client.get("/login", headers={"Accept-Language": "hi-IN,hi;q=0.9,en;q=0.5"}).get_data(as_text=True)
    assert 'lang="hi"' in html
    html = client.get("/login", headers={"Accept-Language": "fr-FR"}).get_data(as_text=True)
    assert 'lang="en"' in html


def test_untranslated_text_falls_back_to_english(client, monkeypatch):
    from app.translations import hi

    monkeypatch.setitem(hi.CATALOG, "Sign in", "")           # an empty/missing entry must not blank the page
    client.get("/login?lang=hi")
    from app import i18n
    monkeypatch.delitem(hi.CATALOG, "Sign in")
    i18n._catalogs.clear()
    assert "Sign in" in client.get("/login").get_data(as_text=True)
    i18n._catalogs.clear()
