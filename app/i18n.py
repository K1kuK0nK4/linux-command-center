"""Interface translation (English by default, Spanish optional).

Screens are written in English. When the language is Spanish, the HTML of every response goes
through translate_html(), which replaces the visible texts (and some attributes) found in
i18n_es.ES. A text is only translated when it matches an entry completely, so user data (server
names, packages, command output) is never touched. Entries with {placeholders} are patterns for
texts with variable parts.

"""
import contextvars
import hashlib
import html
import json
import re

from .i18n_es import ES

LANGS = ("es", "en")
current = contextvars.ContextVar("lang", default="en")


def _compile(table):
    exact = {k: v for k, v in table.items() if "{" not in k}
    patterns = []
    for k, v in table.items():
        if "{" in k:
            rx = re.escape(k)
            rx = re.sub(r"\\\{(\w+)\\\}", lambda m: f"(?P<{m.group(1)}>.+?)", rx)
            # Fixed text before the first and after the last placeholder: a cheap test before the regex
            prefix, suffix = k.split("{", 1)[0], k.rsplit("}", 1)[-1]
            patterns.append((re.compile(f"^{rx}$", re.S), v, prefix, suffix))
    return exact, patterns


# Language -> (exact texts, patterns, table for the browser)
_TABLES = {"es": (*_compile(ES), ES), "en": ({}, [], {})}   # English is the source: nothing to translate

SKIP_TAGS = {"script", "style", "pre", "code", "textarea"}
TAG_RE = re.compile(r"(<[^>]*>)")
ATTR_RE = re.compile(r'\b(placeholder|title|aria-label|data-confirm|alt)="([^"]*)"')


def get_lang():
    return current.get()


_MEMO = {}          # (language, text) -> translation: pages repeat the same texts over and over
_MEMO_MAX = 50_000


def translate_text(s):
    """Translates a whole text (without surrounding spaces) or returns it unchanged."""
    if not s:
        return s
    lang = current.get()
    if lang not in _TABLES or lang == "en":
        return s
    key = (lang, s)
    if key in _MEMO:
        return _MEMO[key]
    exact, patterns, _ = _TABLES[lang]
    out = exact.get(s)
    if out is None:
        out = s
        for rx, target, prefix, suffix in patterns:
            if not (s.startswith(prefix) and s.endswith(suffix)):
                continue
            m = rx.match(s)
            if m:
                parts = {k: exact.get(v, v) for k, v in m.groupdict().items()}
                out = target.format(**parts)
                break
    if len(_MEMO) >= _MEMO_MAX:
        _MEMO.clear()
    _MEMO[key] = out
    return out


def _(s, **kw):
    out = translate_text(s)
    return out.format(**kw) if kw else out


DATE_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):(\d{2})(?::\d{2})?)?\b")


def format_dates(text, fmt):
    """Changes 'YYYY-MM-DD HH:MM:SS' dates to the format chosen in Settings."""
    if fmt == "iso":
        return text

    def repl(m):
        y, mo, d, h, mi = m.groups()
        date = {"eu": f"{d}/{mo}/{y}", "eu_corto": f"{d}/{mo}/{y[2:]}", "us": f"{mo}/{d}/{y}"}.get(fmt, m.group(0))
        if h is None:
            return date
        if fmt == "us":
            hh = int(h) % 12 or 12
            return f"{date} {hh}:{mi} {'PM' if int(h) >= 12 else 'AM'}"
        return f"{date} {h}:{mi}"
    return DATE_RE.sub(repl, text)


def _translate_segment(raw, date_fmt="iso"):
    if not raw or raw.isspace():     # most pieces between tags are just indentation
        return raw
    text = html.unescape(raw) if "&" in raw else raw
    core = text.strip()
    if not core:
        return raw
    norm = SPACES_RE.sub(" ", core) if any(c in core for c in "\n\t  ") else core
    tr = format_dates(translate_text(norm), date_fmt)
    if tr == norm:
        return raw
    lead = text[: len(text) - len(text.lstrip())]
    trail = text[len(text.rstrip()):]
    return lead + html.escape(tr, quote=False) + trail


ATTR_HINTS = ('placeholder="', 'title="', 'aria-label="', 'data-confirm="', 'alt="')
TAG_NAME_RE = re.compile(r"<(/?)\s*([a-zA-Z0-9]+)")
SPACES_RE = re.compile(r"\s+")


def _translate_attrs(tag):
    if not any(h in tag for h in ATTR_HINTS):     # most tags have nothing to translate
        return tag

    def repl(m):
        val = html.unescape(m.group(2))
        tr = translate_text(re.sub(r"\s+", " ", val.strip()))
        return m.group(0) if tr == val.strip() else f'{m.group(1)}="{html.escape(tr)}"'
    return ATTR_RE.sub(repl, tag)


def translate_html(body, date_fmt="iso"):
    out, skip = [], None
    for tok in TAG_RE.split(body):
        if not tok:
            continue
        if tok[0] == "<":
            m = TAG_NAME_RE.match(tok)
            closing, tag = (m.group(1), m.group(2).lower()) if m else ("", "")
            if skip:
                if closing and tag == skip:
                    skip = None
                out.append(tok)
                continue
            if tag in SKIP_TAGS and not closing:
                skip = tag
            out.append(_translate_attrs(tok))
        elif skip:
            out.append(tok)
        else:
            out.append(_translate_segment(tok, date_fmt))
    return "".join(out)


def js_dict():
    """Dictionary for the browser's JavaScript t() in the current language."""
    return _TABLES.get(current.get(), _TABLES["en"])[2]


# The dictionary is served as a separate script (/lang/<code>.js) that the browser keeps in its cache,
# instead of being repeated inside every page. The version changes whenever the texts change.
VERSION = hashlib.sha256(json.dumps(ES, sort_keys=True).encode()).hexdigest()[:12]


def js_source(lang):
    table = _TABLES.get(lang, _TABLES["en"])[2]
    return "window.I18N = " + json.dumps(table, ensure_ascii=False) + ";\n"


def js_src():
    return f"/lang/{current.get()}.js?v={VERSION}"
