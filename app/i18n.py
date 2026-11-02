"""Traducción de la interfaz (español por defecto, inglés opcional).

Las pantallas se escriben en español. Con el idioma en inglés, el HTML de cada respuesta pasa por
translate_html(), que sustituye los textos visibles (y algunos atributos) que estén en el diccionario
i18n_en.EN. Solo se traduce un texto si coincide entero con una entrada, así que los datos del usuario
(nombres de VMs, paquetes, salidas de comandos) no se tocan. Las entradas con {marcadores} sirven de
patrón para textos con partes variables.
"""
import contextvars
import html
import re

from .i18n_en import EN

LANGS = ("es", "en")
current = contextvars.ContextVar("lang", default="es")

_EXACT = {k: v for k, v in EN.items() if "{" not in k}
_PATTERNS = []
for _k, _v in EN.items():
    if "{" in _k:
        rx = re.escape(_k)
        rx = re.sub(r"\\\{(\w+)\\\}", lambda m: f"(?P<{m.group(1)}>.+?)", rx)
        _PATTERNS.append((re.compile(f"^{rx}$", re.S), _v))

SKIP_TAGS = {"script", "style", "pre", "code", "textarea"}
TAG_RE = re.compile(r"(<[^>]*>)")
ATTR_RE = re.compile(r'\b(placeholder|title|aria-label|data-confirm|alt)="([^"]*)"')


def get_lang():
    return current.get()


def translate_text(s):
    """Traduce un texto completo (sin espacios alrededor) o lo devuelve igual."""
    if current.get() != "en" or not s:
        return s
    if s in _EXACT:
        return _EXACT[s]
    for rx, target in _PATTERNS:
        m = rx.match(s)
        if m:
            parts = {k: _EXACT.get(v, v) for k, v in m.groupdict().items()}
            return target.format(**parts)
    return s


def _(s, **kw):
    out = translate_text(s)
    return out.format(**kw) if kw else out


DATE_RE = re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):(\d{2})(?::\d{2})?)?\b")


def format_dates(text, fmt):
    """Cambia las fechas 'AAAA-MM-DD HH:MM:SS' al formato elegido en Ajustes."""
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
    """Diccionario para el JavaScript del navegador (solo cuando el idioma es inglés)."""
    return EN if current.get() == "en" else {}
