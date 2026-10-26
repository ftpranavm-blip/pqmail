"""Tiny, dependency-free translation layer (English + Hindi).

Usage in templates and code::

    {{ _("Inbox") }}
    {{ _("Welcome back, %(email)s!", email=user) }}

The English text itself is the lookup key (like gettext), so an untranslated
string simply renders in English. The active language comes from
``?lang=xx`` (remembered in the session) and falls back to the browser's
``Accept-Language`` header, then English. Long-form educational pages
(Learn, Security) stay in English.

To add a language, create ``app/translations/<code>.py`` exposing a ``CATALOG``
dict and add the code to ``LANGUAGES``.
"""
from __future__ import annotations

import importlib
from typing import Any

from flask import has_request_context, request, session

DEFAULT_LANGUAGE = "en"
LANGUAGES: dict[str, str] = {"en": "English", "hi": "हिन्दी"}

_catalogs: dict[str, dict[str, str]] = {}


def _catalog(lang: str) -> dict[str, str]:
    if lang not in _catalogs:
        try:
            module = importlib.import_module(f"app.translations.{lang}")
            _catalogs[lang] = dict(module.CATALOG)
        except ImportError:
            _catalogs[lang] = {}
    return _catalogs[lang]


def current_language() -> str:
    if not has_request_context():
        return DEFAULT_LANGUAGE
    lang = session.get("lang")
    if lang in LANGUAGES:
        return lang
    best = request.accept_languages.best_match(list(LANGUAGES), default=DEFAULT_LANGUAGE)
    return best or DEFAULT_LANGUAGE


def gettext(text: str, **values: Any) -> str:
    """Translate ``text`` into the active language and fill ``%(name)s`` fields."""
    lang = current_language()
    out = _catalog(lang).get(text, text) if lang != DEFAULT_LANGUAGE else text
    if not values:
        # No placeholders: a literal percent sign is written "%%" in the source text.
        return out.replace("%%", "%")
    try:
        return out % values
    except (KeyError, ValueError, TypeError):
        # a broken translation must never take the page down: fall back to English
        try:
            return text % values
        except (KeyError, ValueError, TypeError):
            return text


def select_language_from_request() -> None:
    """``before_request`` hook: honour ``?lang=`` and remember it."""
    lang = request.args.get("lang")
    if lang in LANGUAGES:
        session["lang"] = lang


# Pages that only exist as the *result of a POST* have no URL you can simply reload
# with ``?lang=``; the language links on them go to the matching GET page instead.
_POST_RESULT_PAGES = {
    "pqmail.qkd_run": "pqmail.qkd_page",
    "pqmail.attack_lab_run": "pqmail.attack_lab_page",
    "pqmail.compose_submit": "pqmail.compose_page",
    "pqmail.benchmarks_run": "pqmail.benchmarks_page",
    "pqmail.twofa_enable": "pqmail.twofa_setup",
    "pqmail.twofa_disable": "pqmail.twofa_setup",
    "pqmail.twofa_recovery": "pqmail.twofa_setup",
    "pqmail.login_2fa_submit": "pqmail.login_2fa",
}


def lang_url(code: str) -> str:
    """URL of the current page in language ``code`` (never a method-not-allowed link).

    GET pages keep their path *and* query string (page number, filters...). Pages that
    were produced by a POST link to their GET counterpart, or home as a last resort.
    """
    from flask import url_for

    endpoint = request.endpoint
    try:
        if endpoint and endpoint != "static":
            if request.method == "GET":
                args = {**request.args.to_dict(), "lang": code}
                return url_for(endpoint, **{**(request.view_args or {}), **args})
            target = _POST_RESULT_PAGES.get(endpoint)
            if target:
                return url_for(target, lang=code)
    except Exception:  # noqa: BLE001 - never let the language switcher break a page
        pass
    return url_for("pqmail.index", lang=code)


def init_i18n(app) -> None:
    app.before_request(select_language_from_request)
    app.jinja_env.globals["_"] = gettext
    app.jinja_env.globals["current_language"] = current_language
    app.jinja_env.globals["LANGUAGES"] = LANGUAGES
    app.jinja_env.globals["lang_url"] = lang_url
