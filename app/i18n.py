"""Interface translation (English by default, Spanish optional).

Screens are written in English. When the language is Spanish, the HTML of every response goes
through translate_html(), which replaces the visible texts (and some attributes) found in
i18n_es.ES. A text is only translated when it matches an entry completely, so user data (server
names, packages, command output) is never touched. Entries with {placeholders} are patterns for
texts with variable parts.

"""
import contextvars
import html
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
            patterns.append((re.compile(f"^{rx}$", re.S), v))
    return exact, patterns


# Language -> (exact texts, patterns, table for the browser)
_TABLES = {"es": (*_compile(ES), ES), "en": ({}, [], {})}   # English is the source: nothing to translate

SKIP_TAGS = {"script", "style", "pre", "code", "textarea"}
TAG_RE = re.compile(r"(<[^>]*>)")
ATTR_RE = re.compile(r'\b(placeholder|title|aria-label|data-confirm|alt)="([^"]*)"')


def get_lang():
    return current.get()


def translate_text(s):
    """Translates a whole text (without surrounding spaces) or returns it unchanged."""
    if not s:
        return s
    exact, patterns, _ = _TABLES.get(current.get(), _TABLES["en"])
    if s in exact:
        return exact[s]
    for rx, target in patterns:
        m = rx.match(s)
        if m:
            parts = {k: exact.get(v, v) for k, v in m.groupdict().items()}
            return target.format(**parts)
    return s


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
    text = html.unescape(raw)
    core = text.strip()
    if not core:
        return raw
    norm = re.sub(r"\s+", " ", core)
    tr = format_dates(translate_text(norm), date_fmt)
    if tr == norm:
        return raw
    lead = text[: len(text) - len(text.lstrip())]
    trail = text[len(text.rstrip()):]
    return lead + html.escape(tr, quote=False) + trail


def _translate_attrs(tag):
    def repl(m):
        val = html.unescape(m.group(2))
        tr = translate_text(re.sub(r"\s+", " ", val.strip()))
        return m.group(0) if tr == val.strip() else f'{m.group(1)}="{html.escape(tr)}"'
    return ATTR_RE.sub(repl, tag)


def translate_html(body, date_fmt="iso"):
    out, skip = [], None
    for tok in TAG_RE.split(body):
        if tok.startswith("<"):
            m = re.match(r"<(/?)\s*([a-zA-Z0-9]+)", tok)
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
