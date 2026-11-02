"""Linux Command Center: aplicación web (FastAPI)."""
import asyncio
import csv
from contextlib import asynccontextmanager
import io
import json
import os
import posixpath
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
from datetime import datetime
from urllib.parse import quote, urlencode, urlparse
from zoneinfo import ZoneInfo

import asyncssh
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import (FileResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask

from . import (backup, charts, collector, db, files, i18n, jobs, safety, ssh, syslog, terminal, transfer,
               versions)
from .vault import derive as derive_key
from .vault import vault

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_COOKIE = "invvm_session"
SESSION_IDLE = 2 * 3600

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))
sessions = {}


# ---------- utilidades de plantilla ----------

def _parse_ts(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=db.TZ)
    except (TypeError, ValueError):
        return None


def days_since(ts):
    d = _parse_ts(ts)
    return None if d is None else (datetime.now(db.TZ) - d).days


def ago(ts):
    d = _parse_ts(ts)
    if d is None:
        return "nunca"
    secs = int((datetime.now(db.TZ) - d).total_seconds())
    if secs < 60:
        return "hace un momento"
    if secs < 3600:
        return f"hace {secs // 60} min"
    if secs < 86400:
        return f"hace {secs // 3600} h"
    return f"hace {secs // 86400} días"


def uptime(s):
    if s is None:
        return "—"
    d, h = s // 86400, (s % 86400) // 3600
    return f"{d} d {h} h" if d else f"{h} h {(s % 3600) // 60} min"


templates.env.filters["ago"] = ago
templates.env.filters["days_since"] = days_since
templates.env.filters["uptime"] = uptime


def fingerprint(host_key):
    try:
        return asyncssh.import_public_key(host_key).get_fingerprint("sha256")
    except Exception:
        return ""


templates.env.filters["fingerprint"] = fingerprint

# Nombres legibles de las acciones de auditoría (en la base de datos se guarda el código)
AUDIT_ACTIONS = {
    "setup": "Contraseña maestra creada", "login": "Inicio de sesión", "login_fallido": "Inicio de sesión fallido",
    "bloqueo": "Aplicación bloqueada", "aviso_legal_aceptado": "Aviso legal aceptado",
    "verificacion_ok": "Contraseña maestra confirmada", "verificacion_fallida": "Confirmación fallida",
    "clave_reforzada": "Contraseña maestra reforzada", "password_maestra": "Contraseña maestra cambiada",
    "vm_creada": "Servidor creado", "vm_editada": "Servidor editado", "vm_eliminada": "Servidor eliminado",
    "importacion": "Importación de servidores", "exportacion": "Exportación de servidores",
    "escaneo": "Escaneo", "escaneo_automatico": "Escaneo automático",
    "contenedores_sudo": "Contenedores leídos con sudo",
    "hostkey_nueva": "Huella SSH guardada", "hostkey_known_hosts": "Huella SSH desde known_hosts",
    "hostkey_aceptada": "Huella SSH aceptada", "hostkey_rechazada": "Huella SSH rechazada",
    "hostkey_reset": "Huella SSH reiniciada", "huellas_config": "Configuración de huellas SSH",
    "terminal_abierta": "Terminal abierta", "terminal_cerrada": "Terminal cerrada",
    "terminal_peligroso_confirmado": "Comando peligroso confirmado (terminal)",
    "comando_masivo": "Ejecución remota", "comando_peligroso_confirmado": "Comando peligroso confirmado",
    "comando_guardado": "Comando guardado", "comando_eliminado": "Comando eliminado",
    "fichero_descargado": "Fichero descargado", "fichero_subido": "Fichero subido",
    "carpeta_creada": "Carpeta creada", "fichero_borrado": "Fichero borrado",
    "credencial_creada": "Credencial creada", "credencial_editada": "Credencial editada",
    "credencial_eliminada": "Credencial eliminada", "credencial_revelada": "Contraseña mostrada",
    "catalogo_renombrado": "Cliente/entorno renombrado", "catalogo_eliminado": "Cliente/entorno eliminado",
    "auditoria_verificada": "Auditoría verificada", "auditoria_exportada": "Auditoría descargada",
    "syslog_configurado": "Envío a syslog configurado", "sondas": "Detección de versiones modificada",
    "modo_seguro": "Modo seguro", "ajustes": "Ajustes modificados", "copia_seguridad": "Copia exacta descargada",
    "exportacion_completa": "Exportación completa", "importacion_completa": "Importación completa",
    "restauracion": "Copia restaurada", "limpieza_historial": "Limpieza del historial",
}
templates.env.filters["action_label"] = lambda code: AUDIT_ACTIONS.get(code, code)
templates.env.globals["APP_NAME"] = "Linux Command Center"
# Autoría que aparece en el menú, el inicio de sesión y el aviso legal
templates.env.globals["AUTHOR_NAME"] = "@fmunozcano"
templates.env.globals["AUTHOR_URL"] = "https://www.linkedin.com/in/fmunozcano/"
templates.env.globals["_"] = i18n._
templates.env.globals["get_lang"] = i18n.get_lang
templates.env.globals["js_i18n"] = i18n.js_dict
templates.env.globals["auth_need"] = lambda vm: ssh.needs(vm)
# Cambiar este número obliga a volver a aceptar el aviso legal
DISCLAIMER_VERSION = "1"

# La auditoría se firma con una clave que solo está disponible con la aplicación desbloqueada
db.audit_key_fn = vault.audit_key

# ---------- preferencias de apariencia ----------
ACCENTS = {"azul": "#3b7be8", "verde": "#16a34a", "morado": "#8b5cf6", "naranja": "#ea7317",
           "turquesa": "#0d9488", "rojo": "#dc2626", "rosa": "#db2777"}
DATE_FORMATS = {"iso": "2026-10-30 13:45", "eu": "30/10/2026 13:45", "eu_corto": "30/10/26 13:45",
                "us": "10/30/2026 1:45 PM"}
TIMEZONES = ["Europe/Madrid", "Atlantic/Canary", "Europe/Lisbon", "Europe/London", "UTC", "America/Mexico_City",
             "America/Bogota", "America/Lima", "America/Santiago", "America/Buenos_Aires", "America/New_York"]
VM_COLUMNS = {"client": "Cliente", "os": "SO", "kernel": "Kernel", "pkgs": "Paquetes", "pending": "Pendientes",
              "last_update": "Última actualización", "last_check": "Último escaneo", "status": "Estado",
              "environment": "Entorno", "hostname": "Hostname", "arch": "Arquitectura", "uptime": "Tiempo encendido",
              "reboot": "Requiere reinicio", "credential": "Credencial", "containers": "Contenedores"}
DEFAULT_VM_COLUMNS = ["client", "os", "kernel", "pkgs", "containers", "pending", "last_update", "last_check", "status"]
PREF_DEFAULTS = {"theme": "auto", "accent": "azul", "density": "normal", "date_format": "iso",
                 "timezone": os.environ.get("TZ", "Europe/Madrid")}


def prefs():
    p = {k: db.get_setting(f"pref_{k}", d) for k, d in PREF_DEFAULTS.items()}
    p["accent_hex"] = ACCENTS.get(p["accent"], ACCENTS["azul"])
    try:
        cols = [c for c in json.loads(db.get_setting("pref_vm_columns", "null") or "null") or [] if c in VM_COLUMNS]
    except ValueError:
        cols = []
    p["vm_columns"] = cols or DEFAULT_VM_COLUMNS
    return p


def apply_timezone():
    try:
        db.TZ = ZoneInfo(prefs()["timezone"])
    except Exception:
        pass


templates.env.globals["prefs"] = prefs
# Opciones para los desplegables de selección múltiple (_multi.html)
templates.env.globals["zip_pairs"] = lambda values: [(v, v) for v in values]
templates.env.globals["tag_options"] = lambda tags: [(str(t["id"]), f"{t['name']} ({t['vm_count']})") for t in tags]
templates.env.globals["VM_COLUMNS"] = VM_COLUMNS


def detected(col, containers=False):
    """Valores de familia o distribución que hay en el inventario (y en los contenedores, si se pide)."""
    sql = f"SELECT {col} FROM vms WHERE COALESCE({col},'')<>''"
    if containers:
        sql += f" UNION SELECT {col} FROM containers WHERE COALESCE({col},'')<>''"
    return sorted({r[0] for r in db.q(sql)}, key=str.lower)


templates.env.globals["family_options"] = lambda containers=False: [
    (f, charts.FAMILY.get(f, f)) for f in detected("os_family", containers)] + [(charts.NONE_VALUE, "(sin datos)")]
templates.env.globals["distro_options"] = lambda containers=False: [
    (d, d) for d in detected("os_name", containers)] + [(charts.NONE_VALUE, "(sin datos)")]

NONE_VALUE = charts.NONE_VALUE
TAG_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]


def all_tags():
    return db.q("""SELECT t.*, (SELECT COUNT(*) FROM vm_tags WHERE tag_id=t.id) vm_count
                   FROM tags t ORDER BY name COLLATE NOCASE""")


def tags_by_vm():
    out = {}
    for r in db.q("SELECT vt.vm_id, t.id, t.name, t.color FROM vm_tags vt JOIN tags t ON t.id=vt.tag_id "
                  "ORDER BY t.name COLLATE NOCASE"):
        out.setdefault(r["vm_id"], []).append(r)
    return out


def get_or_create_tag(name):
    name = name.strip()[:40]
    row = db.q1("SELECT id FROM tags WHERE name=?", (name,))
    if row:
        return row["id"]
    n = db.q1("SELECT COUNT(*) n FROM tags")["n"]
    return db.ex("INSERT INTO tags(name, color) VALUES(?,?)", (name, TAG_COLORS[n % len(TAG_COLORS)]))


def set_vm_tags(vm_id, tag_ids, new_names=""):
    ids = {int(t) for t in tag_ids if str(t).isdigit()}
    ids |= {get_or_create_tag(n) for n in new_names.split(",") if n.strip()}
    with db.tx() as c:
        c.execute("DELETE FROM vm_tags WHERE vm_id=?", (vm_id,))
        c.executemany("INSERT OR IGNORE INTO vm_tags(vm_id, tag_id) VALUES(?,?)", [(vm_id, t) for t in ids])


def render(request, name, **ctx):
    return templates.TemplateResponse(request, name, ctx)


def redirect(url):
    return RedirectResponse(url, status_code=303)


def csv_response(filename, header, rows):
    buf = io.StringIO()
    buf.write("﻿")
    w = csv.writer(buf, delimiter=";")
    w.writerow(header)
    w.writerows([[transfer.safe_cell(v) for v in row] for row in rows])
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------- sesión y seguridad ----------

# Peticiones que hace la página sola cada pocos segundos: no cuentan como actividad de la persona
PASSIVE_PATHS = ("/api/activity", "/api/charts", "/api/scan/status", "/api/jobs/")
last_activity = time.time()


def valid_session(request_or_ws, touch=True):
    global last_activity
    token = request_or_ws.cookies.get(SESSION_COOKIE)
    exp = sessions.get(token)
    if not token or not exp or exp < time.time() or not vault.unlocked:
        sessions.pop(token, None)
        return False
    if touch:
        sessions[token] = time.time() + SESSION_IDLE
        last_activity = time.time()
    return True


def lock_all(reason):
    global stepup_until
    stepup_until = 0.0
    sessions.clear()
    vault.lock()
    ssh.session_auth.clear()
    db.audit("bloqueo", reason)


def busy():
    """Hay trabajo en marcha que necesita la clave: no se bloquea automáticamente."""
    return bool(collector.running or terminal.ACTIVE or db.q1("SELECT 1 FROM jobs WHERE finished_at IS NULL"))


def same_origin(headers):
    origin = headers.get("origin")
    if not origin:
        return True
    return urlparse(origin).netloc == headers.get("host")


PUBLIC = ("/login", "/setup", "/static/", "/lang")
LANG_COOKIE = "lcc_lang"


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    lang = request.cookies.get(LANG_COOKIE)
    i18n.current.set(lang if lang in i18n.LANGS else "es")
    if request.method not in ("GET", "HEAD") and not same_origin(request.headers):
        return PlainTextResponse("Origen no permitido", status_code=403)
    if not path.startswith(PUBLIC):
        if not vault.initialized:
            return redirect("/setup")
        passive = request.method == "GET" and path.startswith(PASSIVE_PATHS)
        if not valid_session(request, touch=not passive):
            if path.startswith("/api/"):
                return JSONResponse({"error": "sesión caducada"}, status_code=401)
            return redirect("/login")
        if (db.get_setting("disclaimer_version") != DISCLAIMER_VERSION
                and not path.startswith(("/disclaimer", "/logout", "/api/"))):
            return redirect("/disclaimer")
    response = await call_next(request)
    date_fmt = db.get_setting("pref_date_format", "iso") if vault.initialized else "iso"
    if ((i18n.get_lang() == "en" or date_fmt != "iso")
            and response.headers.get("content-type", "").startswith("text/html")):
        body = b"".join([chunk async for chunk in response.body_iterator])
        headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
        response = Response(i18n.translate_html(body.decode("utf-8"), date_fmt), status_code=response.status_code,
                            headers=headers, media_type="text/html")
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    # CSP: aunque se colara un script (p. ej. con datos maliciosos de un servidor), no podría enviar nada fuera
    # ni cargar recursos externos. Las páginas usan scripts en línea, por eso 'unsafe-inline'.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'")
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), usb=()"
    return response


def new_session(response):
    token = secrets.token_urlsafe(32)
    sessions[token] = time.time() + SESSION_IDLE
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict")
    return response


@app.post("/lang")
async def set_lang(request: Request):
    form = await request.form()
    lang = form.get("lang") if form.get("lang") in i18n.LANGS else "es"
    nxt = form.get("next", "/")
    resp = redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
    resp.set_cookie(LANG_COOKIE, lang, max_age=10 * 365 * 86400, samesite="strict")
    return resp


@app.get("/disclaimer")
async def disclaimer(request: Request):
    accepted = db.get_setting("disclaimer_accepted_at") if db.get_setting("disclaimer_version") == DISCLAIMER_VERSION else None
    return render(request, "disclaimer.html", accepted=accepted)


@app.post("/disclaimer")
async def disclaimer_accept(request: Request):
    form = await request.form()
    if form.get("accept"):
        db.set_setting("disclaimer_version", DISCLAIMER_VERSION)
        db.set_setting("disclaimer_accepted_at", db.now())
        db.audit("aviso_legal_aceptado", f"versión {DISCLAIMER_VERSION}")
        return redirect("/")
    return redirect("/disclaimer")


@app.get("/setup")
async def setup_form(request: Request):
    if vault.initialized:
        return redirect("/login")
    return render(request, "setup.html")


@app.post("/setup")
async def setup(request: Request):
    if vault.initialized:
        return redirect("/login")
    form = await request.form()
    pw, pw2 = form.get("password", ""), form.get("password2", "")
    if len(pw) < 10:
        return render(request, "setup.html", error="La contraseña debe tener al menos 10 caracteres.")
    if pw != pw2:
        return render(request, "setup.html", error="Las contraseñas no coinciden.")
    salt = os.urandom(16)
    vault.setup_with_key(await asyncio.to_thread(derive_key, pw, salt), salt)
    db.audit("setup", "Contraseña maestra creada")
    return new_session(redirect("/"))


async def check_master(password):
    """Comprueba la contraseña maestra (el cálculo lento va en un hilo aparte)."""
    key = await asyncio.to_thread(vault.derive_for, password or "")
    return vault.unlock_with_key(key)


# Doble verificación: acciones sensibles piden la contraseña maestra (válida 5 minutos)
STEPUP_SECONDS = 300
stepup_until = 0.0


def stepup_valid():
    return time.time() < stepup_until


async def stepup(password, what):
    global stepup_until
    if not await check_master(password):
        db.audit("verificacion_fallida", what)
        await asyncio.sleep(1)
        return False
    stepup_until = time.time() + STEPUP_SECONDS
    db.audit("verificacion_ok", what)
    return True


async def upgrade_kdf(password):
    """Si la clave se creó con parámetros antiguos, se vuelve a derivar con los actuales."""
    if vault.needs_upgrade():
        salt = os.urandom(16)
        vault.rekey(await asyncio.to_thread(derive_key, password, salt), salt)
        db.audit("clave_reforzada", "Contraseña maestra migrada a scrypt N=2^17")


@app.get("/login")
async def login_form(request: Request):
    if not vault.initialized:
        return redirect("/setup")
    return render(request, "login.html")


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    if not await check_master(form.get("password", "")):
        db.audit("login_fallido", request.client.host if request.client else "")
        await asyncio.sleep(1.5)
        return render(request, "login.html", error="Contraseña incorrecta.")
    db.audit("login", "")
    await upgrade_kdf(form.get("password", ""))
    return new_session(redirect("/"))


@app.post("/logout")
async def logout(request: Request):
    lock_all("Aplicación bloqueada manualmente")
    resp = redirect("/login")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---------- panel ----------

@app.get("/")
async def dashboard(request: Request):
    total = db.q1("SELECT COUNT(*) n FROM vms")["n"]
    stats = db.q1("""SELECT
        SUM(last_scan_status='ok') ok, SUM(last_scan_status='error') err, SUM(last_scan_status='never') never,
        SUM(reboot_required=1) reboot, SUM(pending_security>0) sec,
        SUM(last_pkg_update IS NOT NULL AND last_pkg_update < datetime('now','localtime','-30 days')) stale_upd,
        SUM(last_ok_at IS NULL OR last_ok_at < datetime('now','localtime','-7 days')) stale_scan
        FROM vms""")
    clients = db.q("""SELECT COALESCE(client,'') c, COUNT(*) n, SUM(last_scan_status='error') err, MAX(last_ok_at) last_ok
                      FROM vms GROUP BY 1 ORDER BY n DESC""")
    errors = db.q("SELECT id, name, host, last_scan_error, last_scan_at FROM vms WHERE last_scan_status='error' "
                  "ORDER BY name LIMIT 20")
    stale = db.q("SELECT id, name, client, last_pkg_update FROM vms WHERE last_pkg_update IS NOT NULL "
                 "ORDER BY last_pkg_update LIMIT 10")
    seed_charts()
    return render(request, "dashboard.html", total=total, stats=stats, clients=clients, errors=errors, stale=stale,
                  dimensions=charts.DIMENSIONS, kinds=charts.KINDS, tags=all_tags(),
                  all_clients=distinct("client"), envs=distinct("environment"))


# ---------- servidores ----------

MULTI_FILTERS = ("client", "environment", "tag", "os_family", "os_name")


def query_dict(request):
    """Parámetros de la URL; cliente, entorno, etiqueta, familia y distribución pueden repetirse (selección múltiple)."""
    p = dict(request.query_params)
    for key in MULTI_FILTERS:
        p[key] = [v for v in request.query_params.getlist(key) if v]
    return p


def as_list(value):
    if not value:
        return []
    return [v for v in value if v] if isinstance(value, (list, tuple)) else [value]


def in_clause(column, values):
    return f"{column} IN ({','.join('?' * len(values))})"


def multi_where(params, where, args, prefix, columns=None):
    """Condiciones de cliente / entorno / etiqueta / familia / distribución (uno o varios valores;
    "__none__" = sin valor). columns permite cambiar la columna de un campo (p. ej. la del contenedor)."""
    for field in ("client", "environment", "os_family", "os_name"):
        vals = as_list(params.get(field))
        if vals:
            column = (columns or {}).get(field, f"{prefix}.{field}")
            where.append(in_clause(f"COALESCE({column},'')", vals))
            args += ["" if v == NONE_VALUE else v for v in vals]
    tags = [int(t) for t in as_list(params.get("tag")) if str(t).isdigit()]
    if tags:
        where.append(f"{prefix}.id IN (SELECT vm_id FROM vm_tags WHERE {in_clause('tag_id', tags)})")
        args += tags


def vm_filters(params):
    where, args = [], []
    if params.get("q"):
        where.append("(vms.name LIKE ? OR vms.host LIKE ? OR vms.hostname LIKE ? OR vms.os_name LIKE ? OR "
                     "vms.kernel LIKE ? OR vms.id IN "
                     "(SELECT vm_id FROM vm_tags JOIN tags ON tags.id=tag_id WHERE tags.name LIKE ?))")
        args += [f"%{params['q']}%"] * 6
    multi_where(params, where, args, "vms")
    # Filtros exactos; "__none__" significa "sin valor"
    for field in ("os_version", "kernel"):
        if params.get(field):
            where.append(f"COALESCE(vms.{field},'')=?")
            args.append("" if params[field] == NONE_VALUE else params[field])
    if params.get("status"):
        where.append("vms.last_scan_status=?")
        args.append(params["status"])
    if params.get("reboot"):
        where.append("vms.reboot_required=1")
    if params.get("containers") == "yes":
        where.append("vms.container_count IS NOT NULL")
    elif params.get("containers") == "no":
        where.append("vms.container_count IS NULL")
    return ("WHERE " + " AND ".join(where)) if where else "", args


CATALOG_KINDS = {"client": "Clientes", "environment": "Entornos"}


def distinct(col):
    values = {r[0] for r in db.q(f"SELECT DISTINCT {col} FROM vms WHERE {col} IS NOT NULL AND {col}<>''")}
    if col in CATALOG_KINDS:
        values |= {r["name"] for r in db.q("SELECT name FROM catalog WHERE kind=?", (col,))}
    return sorted(values, key=str.lower)


def ensure_catalog(kind, name):
    if name:
        db.ex("INSERT OR IGNORE INTO catalog(kind, name) VALUES(?,?)", (kind, name))


@app.get("/vms")
async def vm_list(request: Request):
    p = query_dict(request)
    where, args = vm_filters(p)
    vms = db.q(f"SELECT vms.*, credentials.name cred_name FROM vms LEFT JOIN credentials ON credentials.id=credential_id "
               f"{where} ORDER BY client, name", args)
    return render(request, "vms.html", vms=vms, p=p, clients=distinct("client"), envs=distinct("environment"),
                  running=collector.running, tags=all_tags(), vm_tags=tags_by_vm(),
                  pending_hostkeys=db.q1("SELECT COUNT(*) n FROM vms WHERE pending_host_key IS NOT NULL")["n"])


@app.post("/api/vms/tags")
async def api_vm_tags(request: Request):
    body = await request.json()
    ids = [int(i) for i in body.get("ids", [])]
    if not ids or not (body.get("tag_id") or body.get("name", "").strip()):
        return JSONResponse({"error": "Selecciona servidores y una etiqueta"}, status_code=400)
    tag_id = int(body["tag_id"]) if body.get("tag_id") else get_or_create_tag(body["name"])
    with db.tx() as c:
        if body.get("action") == "remove":
            c.executemany("DELETE FROM vm_tags WHERE vm_id=? AND tag_id=?", [(i, tag_id) for i in ids])
        else:
            c.executemany("INSERT OR IGNORE INTO vm_tags(vm_id, tag_id) VALUES(?,?)", [(i, tag_id) for i in ids])
    db.bump()
    return {"ok": True}


@app.get("/vms/export.csv")
async def vm_export(request: Request):
    where, args = vm_filters(query_dict(request))
    rows = db.q(f"SELECT * FROM vms {where} ORDER BY client, name", args)
    tmap = tags_by_vm()
    return csv_response("inventario_vms.csv",
                        ["Nombre", "Host", "Puerto", "Cliente", "Entorno", "Etiquetas", "Hostname", "SO", "Versión",
                         "Kernel", "Arquitectura", "Paquetes", "Contenedores", "Act. pendientes", "Act. seguridad",
                         "Reinicio requerido",
                         "Última actualización paquetes", "Último escaneo correcto", "Estado último escaneo", "Error"],
                        [(r["name"], r["host"], r["port"], r["client"], r["environment"],
                          ", ".join(t["name"] for t in tmap.get(r["id"], [])), r["hostname"],
                          r["os_name"], r["os_version"], r["kernel"], r["arch"], r["pkg_count"],
                          "sin Docker/Podman" if r["container_count"] is None else r["container_count"],
                          r["pending_updates"],
                          r["pending_security"], "sí" if r["reboot_required"] else "no", r["last_pkg_update"],
                          r["last_ok_at"], r["last_scan_status"], r["last_scan_error"]) for r in rows])


def vm_form_values(form):
    try:
        port = int(form.get("port") or 22)
    except ValueError:
        port = 22
    def pick(field):
        # Desplegable con opción "+ Crear nuevo…" que muestra un campo de texto
        value = form.get(field, "").strip()
        if value == "__new__":
            value = form.get(f"{field}_new", "").strip()[:60]
        ensure_catalog(field, value)
        return value

    return {
        "name": form.get("name", "").strip(),
        "host": form.get("host", "").strip(),
        "port": port,
        "client": pick("client"),
        "environment": pick("environment"),
        "notes": form.get("notes", "").strip(),
    }


def shared_creds():
    return db.q("SELECT id, name, username FROM credentials WHERE owner_vm_id IS NULL ORDER BY name")


def set_own_credential(vm_id, username, password, sudo_password, forget_password=False):
    """Crea o actualiza la credencial propia de un servidor.

    Contraseñas vacías = mantener las guardadas (o, si no hay, pedirlas al conectar).
    forget_password borra las contraseñas guardadas para que se pidan siempre al conectar.
    """
    own = db.q1("SELECT id FROM credentials WHERE owner_vm_id=?", (vm_id,))
    fields = {"username": username}
    for col, val in (("password_enc", password), ("sudo_password_enc", sudo_password)):
        if forget_password:
            fields[col] = None
        elif val or not own:
            fields[col] = vault.encrypt(val)
    if own:
        cred_id = own["id"]
        db.ex(f"UPDATE credentials SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", (*fields.values(), cred_id))
    else:
        cred_id = db.ex(f"INSERT INTO credentials(name, owner_vm_id, created_at, {', '.join(fields)}) "
                        f"VALUES(?,?,?,{','.join('?' * len(fields))})",
                        (f"__vm{vm_id}", vm_id, db.now(), *fields.values()))
    db.ex("UPDATE vms SET credential_id=? WHERE id=?", (cred_id, vm_id))


def save_vm_credential(vm_id, form):
    mode = form.get("cred_mode")
    if mode == "own":
        username = form.get("own_username", "").strip()
        if username:
            set_own_credential(vm_id, username, form.get("own_password", ""), form.get("own_sudo_password", ""),
                               forget_password=bool(form.get("own_forget_password")))
            return
        mode = "ask"  # sin usuario no hay nada que guardar: se pedirá todo al conectar
    if mode == "ask":
        db.ex("UPDATE vms SET credential_id=NULL WHERE id=?", (vm_id,))
        db.ex("DELETE FROM credentials WHERE owner_vm_id=?", (vm_id,))
        ssh.session_auth.pop(vm_id, None)
        return
    cred = form.get("credential_id", "")
    db.ex("UPDATE vms SET credential_id=? WHERE id=?", (int(cred) if cred.isdigit() else None, vm_id))
    db.ex("DELETE FROM credentials WHERE owner_vm_id=?", (vm_id,))


def save_jump(vm_id, form):
    """Bastión: otro servidor del inventario por el que pasa la conexión. Se evitan los bucles."""
    value = form.get("jump_vm_id", "")
    jump_id = int(value) if value.isdigit() else None
    seen = {vm_id}
    current = jump_id
    while current:
        if current in seen:
            jump_id = None
            break
        seen.add(current)
        row = db.q1("SELECT jump_vm_id FROM vms WHERE id=?", (current,))
        current = row["jump_vm_id"] if row else None
    db.ex("UPDATE vms SET jump_vm_id=? WHERE id=?", (jump_id, vm_id))


def vm_form(request, vm, error=None, draft=None):
    own = db.q1("SELECT username, password_enc, sudo_password_enc FROM credentials WHERE owner_vm_id=?",
                (vm["id"],)) if vm else None
    jumps = db.q("SELECT id, name, host, client FROM vms WHERE id<>? ORDER BY client, name", (vm["id"] if vm else 0,))
    return render(request, "vm_form.html", vm=vm, own=own, creds=shared_creds(), clients=distinct("client"), jumps=jumps,
                  envs=distinct("environment"), tags=all_tags(), error=error, draft=draft,
                  vm_tag_ids={t["id"] for t in tags_by_vm().get(vm["id"], [])} if vm else set())


def find_duplicate(client, host, port, exclude_id=None):
    """Misma IP/hostname y puerto dentro del mismo cliente (en clientes distintos sí se permite)."""
    return db.q1("SELECT id, name FROM vms WHERE COALESCE(client,'')=? AND host=? COLLATE NOCASE AND port=? "
                 "AND id<>?", (client or "", host, port, exclude_id or 0))


def duplicate_message(dup, v):
    return (f"Ya existe el servidor «{dup['name']}» con {v['host']}:{v['port']} en el cliente "
            f"«{v['client'] or 'sin cliente'}». Revisa la IP o el cliente.")


@app.get("/vms/new")
async def vm_new(request: Request):
    return vm_form(request, None)


@app.post("/vms/new")
async def vm_create(request: Request):
    form = await request.form()
    v = vm_form_values(form)
    if not v["name"] or not v["host"]:
        return redirect("/vms/new")
    dup = find_duplicate(v["client"], v["host"], v["port"])
    if dup:
        return vm_form(request, None, error=duplicate_message(dup, v), draft=v)
    vm_id = db.ex("INSERT INTO vms(name, host, port, client, environment, notes, created_at) VALUES(?,?,?,?,?,?,?)",
                  (*v.values(), db.now()))
    save_vm_credential(vm_id, form)
    save_jump(vm_id, form)
    set_vm_tags(vm_id, form.getlist("tag_ids"), form.get("new_tags", ""))
    db.bump()
    db.audit("vm_creada", f"{v['name']} ({v['host']})")
    return redirect(f"/vms/{vm_id}")


def transfer_page(request, **ctx):
    return render(request, "import.html", creds=shared_creds(), columns=transfer.COLUMNS, clients=distinct("client"),
                  tags=all_tags(), total=db.q1("SELECT COUNT(*) n FROM vms")["n"], **ctx)


def file_response(content, filename, media_type):
    return Response(content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@app.get("/vms/import")
async def vm_import_form(request: Request):
    return transfer_page(request)


@app.get("/vms/import/plantilla.{fmt}")
async def vm_import_template(fmt: str):
    rows = [{"nombre": "web01-pro", "host": "10.0.0.10", "puerto": "22", "cliente": "ClienteA", "entorno": "PRO",
             "etiquetas": "web, dmz", "usuario": "analista", "password": "CambiaEsto123"},
            {"nombre": "db01-pro", "host": "10.0.0.11", "cliente": "ClienteA", "entorno": "PRO", "etiquetas": "bbdd",
             "credencial": "clienteA-analista", "notas": "Usa la credencial compartida"}]
    if fmt == "csv":
        return file_response(transfer.write_csv(rows), "plantilla_vms.csv", "text/csv; charset=utf-8")
    return file_response(transfer.write_xlsx(rows, False), "plantilla_vms.xlsx", XLSX)


def import_rows(rows, update):
    creds = {r["name"].lower(): r["id"] for r in shared_creds()}
    # Un servidor es "la misma" si coincide cliente + host + puerto (clientes distintos pueden repetir IP privada)
    existing = {((r["client"] or "").lower(), r["host"].lower(), r["port"]): r["id"]
                for r in db.q("SELECT id, client, host, port FROM vms")}
    tmap = tags_by_vm()
    added = updated = skipped = 0
    errors = []
    for n, row in rows:
        host = row.get("host", "")
        if not host:
            errors.append(f"Fila {n}: falta el host (IP), se ignora")
            continue
        port_txt = row.get("puerto", "") or "22"
        if not port_txt.isdigit() or not 0 < int(port_txt) < 65536:
            errors.append(f"Fila {n}: puerto '{port_txt}' no válido, se ignora")
            continue
        port = int(port_txt)
        key = (row.get("cliente", "").lower(), host.lower(), port)
        vm_id = existing.get(key)
        if vm_id and not update:
            skipped += 1
            continue
        fields = {col: row[key] for key, col in (("nombre", "name"), ("cliente", "client"), ("entorno", "environment"),
                                                  ("notas", "notes")) if row.get(key)}
        ensure_catalog("client", fields.get("client"))
        ensure_catalog("environment", fields.get("environment"))
        if vm_id:
            if fields:
                db.ex(f"UPDATE vms SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", (*fields.values(), vm_id))
            updated += 1
        else:
            fields.setdefault("name", host)
            fields.update(host=host, port=port, created_at=db.now())
            vm_id = db.ex(f"INSERT INTO vms({', '.join(fields)}) VALUES({', '.join('?' * len(fields))})",
                          tuple(fields.values()))
            existing[key] = vm_id
            added += 1

        cred_name = row.get("credencial", "")
        if cred_name and cred_name.lower() in creds:
            db.ex("UPDATE vms SET credential_id=? WHERE id=?", (creds[cred_name.lower()], vm_id))
            db.ex("DELETE FROM credentials WHERE owner_vm_id=?", (vm_id,))
        elif row.get("usuario"):
            set_own_credential(vm_id, row["usuario"], row.get("password", ""), row.get("sudo_password", ""))
        elif cred_name:
            errors.append(f"Fila {n}: la credencial '{cred_name}' no existe; el servidor queda sin cambiar de credencial")

        if row.get("etiquetas"):
            set_vm_tags(vm_id, [t["id"] for t in tmap.get(vm_id, [])], row["etiquetas"])
    db.bump()
    return {"added": added, "updated": updated, "skipped": skipped, "errors": errors}


@app.post("/vms/import")
async def vm_import(request: Request):
    form = await request.form()
    upload = form.get("file")
    name = getattr(upload, "filename", "") or ""
    if not name.lower().endswith((".xlsx", ".xlsm", ".csv", ".txt")):
        return transfer_page(request, error="Sube un fichero Excel (.xlsx) o CSV.")
    try:
        rows = transfer.read_rows(name, await upload.read())
    except Exception as e:
        return transfer_page(request, error=f"No se pudo leer el fichero: {e}")
    result = import_rows(rows, form.get("mode") == "update")
    db.audit("importacion", f"{name}: {result['added']} añadidas, {result['updated']} actualizadas, "
                            f"{result['skipped']} ya existían")
    return transfer_page(request, result=result)


@app.post("/vms/export")
async def vm_export_full(request: Request):
    form = await request.form()
    with_pw = bool(form.get("with_passwords"))
    if with_pw and not await check_master(form.get("master_password", "")):
        return transfer_page(request, error="Contraseña maestra incorrecta: no se ha exportado nada.")
    where, args = vm_filters({k: form.get(k, "") for k in ("client", "tag")})
    tmap = tags_by_vm()
    rows = []
    for v in db.q(f"""SELECT vms.*, c.name cred_name, c.username cred_user, c.owner_vm_id cred_own,
                      c.password_enc, c.sudo_password_enc FROM vms LEFT JOIN credentials c ON c.id=vms.credential_id
                      {where} ORDER BY vms.client, vms.name""", args):
        r = {"nombre": v["name"], "host": v["host"], "puerto": v["port"], "cliente": v["client"] or "",
             "entorno": v["environment"] or "", "notas": v["notes"] or "", "usuario": v["cred_user"] or "",
             "etiquetas": ", ".join(t["name"] for t in tmap.get(v["id"], [])),
             "credencial": v["cred_name"] if v["cred_name"] and not v["cred_own"] else ""}
        if with_pw:
            r["password"] = vault.decrypt(v["password_enc"]) or ""
            r["sudo_password"] = vault.decrypt(v["sudo_password_enc"]) or ""
        rows.append(r)
    db.audit("exportacion", f"{len(rows)} servidores{' CON CONTRASEÑAS' if with_pw else ''}")
    stamp = f"{datetime.now(db.TZ):%Y%m%d_%H%M}"
    if form.get("format") == "csv":
        return file_response(transfer.write_csv(rows), f"vms_{stamp}.csv", "text/csv; charset=utf-8")
    return file_response(transfer.write_xlsx(rows, with_pw), f"vms_{stamp}.xlsx", XLSX)


@app.get("/vms/{vm_id}")
async def vm_detail(request: Request, vm_id: int):
    vm = db.q1("SELECT vms.*, credentials.name cred_name, credentials.username cred_user, credentials.owner_vm_id "
               "cred_own FROM vms LEFT JOIN credentials ON credentials.id=credential_id WHERE vms.id=?", (vm_id,))
    if not vm:
        return redirect("/vms")
    jump = db.q1("SELECT id, name, host FROM vms WHERE id=?", (vm["jump_vm_id"],)) if vm["jump_vm_id"] else None
    return render(request, "vm_detail.html", vm=vm, vm_tags=tags_by_vm().get(vm_id, []), jump=jump,
                  packages=db.q("SELECT * FROM packages WHERE vm_id=? ORDER BY container IS NOT NULL, container, name",
                                (vm_id,)),
                  containers=db.q("SELECT * FROM containers WHERE vm_id=? ORDER BY state<>'running', name", (vm_id,)),
                  ports=db.q("SELECT * FROM ports WHERE vm_id=? ORDER BY port", (vm_id,)),
                  services=db.q("SELECT name FROM services WHERE vm_id=? ORDER BY name", (vm_id,)),
                  changes=db.q("SELECT pc.*, sh.finished_at FROM package_changes pc JOIN scan_history sh "
                               "ON sh.id=pc.scan_id WHERE pc.vm_id=? ORDER BY sh.id DESC, pc.name LIMIT 500", (vm_id,)),
                  history=db.q("SELECT * FROM scan_history WHERE vm_id=? ORDER BY id DESC LIMIT 30", (vm_id,)),
                  running=collector.running)


@app.get("/vms/{vm_id}/edit")
async def vm_edit_form(request: Request, vm_id: int):
    vm = db.q1("SELECT * FROM vms WHERE id=?", (vm_id,))
    if not vm:
        return redirect("/vms")
    return vm_form(request, vm)


@app.post("/vms/{vm_id}/edit")
async def vm_edit(request: Request, vm_id: int):
    form = await request.form()
    v = vm_form_values(form)
    dup = find_duplicate(v["client"], v["host"], v["port"], vm_id)
    if dup:
        return vm_form(request, db.q1("SELECT * FROM vms WHERE id=?", (vm_id,)), error=duplicate_message(dup, v),
                       draft=v)
    old = db.q1("SELECT host, port, jump_vm_id FROM vms WHERE id=?", (vm_id,))
    db.ex("UPDATE vms SET name=?, host=?, port=?, client=?, environment=?, notes=? WHERE id=?", (*v.values(), vm_id))
    save_vm_credential(vm_id, form)
    save_jump(vm_id, form)
    set_vm_tags(vm_id, form.getlist("tag_ids"), form.get("new_tags", ""))
    if old and (old["host"], old["port"]) != (v["host"], v["port"]):
        db.ex("UPDATE vms SET host_key=NULL WHERE id=?", (vm_id,))
    db.bump()
    db.audit("vm_editada", v["name"])
    return redirect(f"/vms/{vm_id}")


@app.post("/vms/{vm_id}/delete")
async def vm_delete(request: Request, vm_id: int):
    vm = db.q1("SELECT name FROM vms WHERE id=?", (vm_id,))
    db.ex("DELETE FROM vms WHERE id=?", (vm_id,))
    db.ex("DELETE FROM credentials WHERE owner_vm_id=?", (vm_id,))
    db.ex("UPDATE vms SET jump_vm_id=NULL WHERE jump_vm_id=?", (vm_id,))  # quienes lo usaban de bastión
    db.bump()
    db.audit("vm_eliminada", vm["name"] if vm else str(vm_id))
    return redirect("/vms")


def accept_hostkeys(ids):
    accepted = 0
    for vm in db.q(f"SELECT id, name, host, pending_host_key FROM vms WHERE id IN ({','.join('?' * len(ids))}) "
                   "AND pending_host_key IS NOT NULL", ids) if ids else []:
        db.ex("UPDATE vms SET host_key=pending_host_key, pending_host_key=NULL WHERE id=?", (vm["id"],))
        db.audit("hostkey_aceptada", f"{vm['name']} ({vm['host']}) {fingerprint(vm['pending_host_key'])}")
        accepted += 1
    db.bump()
    return accepted


@app.post("/vms/{vm_id}/accept-hostkey")
async def vm_accept_hostkey(vm_id: int):
    accept_hostkeys([vm_id])
    return redirect(f"/vms/{vm_id}")


@app.post("/vms/{vm_id}/reject-hostkey")
async def vm_reject_hostkey(vm_id: int):
    vm = db.q1("SELECT name, host FROM vms WHERE id=?", (vm_id,))
    db.ex("UPDATE vms SET pending_host_key=NULL WHERE id=?", (vm_id,))
    db.audit("hostkey_rechazada", f"{vm['name']} ({vm['host']})" if vm else str(vm_id))
    return redirect(f"/vms/{vm_id}")


@app.get("/hostkeys")
async def hostkeys_page(request: Request):
    pending = db.q("SELECT id, name, host, port, client, pending_host_key FROM vms WHERE pending_host_key IS NOT NULL "
                   "ORDER BY client, name")
    return render(request, "hostkeys.html", pending=pending, msg=request.query_params.get("msg"))


@app.post("/hostkeys/accept")
async def hostkeys_accept(request: Request):
    form = await request.form()
    n = accept_hostkeys([int(i) for i in form.getlist("ids") if i.isdigit()])
    return redirect("/hostkeys?" + urlencode({"msg": f"{n} huellas aceptadas"}))


@app.post("/settings/hostkeys")
async def settings_hostkeys(request: Request):
    form = await request.form()
    if form.get("hostkey_policy") in ("confirm", "auto"):
        db.set_setting("hostkey_policy", form["hostkey_policy"])
    upload = form.get("known_hosts_file")
    text = form.get("known_hosts", "")
    if upload is not None and getattr(upload, "filename", ""):
        text = (await upload.read()).decode("utf-8", "replace")
    if text.strip() or form.get("clear_known_hosts"):
        if text.strip():
            try:
                asyncssh.import_known_hosts(text)
            except Exception as e:
                return redirect("/settings?" + urlencode({"error": f"known_hosts no válido: {e}"}) + "#huellas")
        db.set_setting("known_hosts", text if not form.get("clear_known_hosts") else "")
    # Los servidores con huella pendiente que estén en el known_hosts se resuelven ya
    resolved = 0
    for vm in db.q("SELECT id, name, host, port FROM vms WHERE host_key IS NULL"):
        key = ssh.known_hosts_key(vm["host"], vm["port"] or 22)
        if key:
            db.ex("UPDATE vms SET host_key=?, pending_host_key=NULL WHERE id=?", (key, vm["id"]))
            resolved += 1
    db.audit("huellas_config", f"política {db.get_setting('hostkey_policy', 'confirm')}, {resolved} servidores resueltas por known_hosts")
    return redirect("/settings?" + urlencode({"msg": f"Guardado. {resolved} servidores han tomado su huella del known_hosts."}) + "#huellas")


@app.post("/vms/{vm_id}/reset-hostkey")
async def vm_reset_hostkey(request: Request, vm_id: int):
    vm = db.q1("SELECT name FROM vms WHERE id=?", (vm_id,))
    db.ex("UPDATE vms SET host_key=NULL WHERE id=?", (vm_id,))
    db.audit("hostkey_reset", vm["name"] if vm else str(vm_id))
    return redirect(f"/vms/{vm_id}")


@app.get("/vms/{vm_id}/terminal")
async def vm_terminal(request: Request, vm_id: int):
    vm = db.q1("SELECT * FROM vms WHERE id=?", (vm_id,))
    if not vm:
        return redirect("/vms")
    become = request.query_params.get("become", "")
    return render(request, "terminal.html", vm=vm, become=become, need=ssh.needs(vm),
                  stepup=not stepup_valid(), safe=safety.enabled(), safe_rules=safety.js_rules())


@app.websocket("/ws/terminal/{vm_id}")
async def ws_terminal(ws: WebSocket, vm_id: int):
    if not same_origin(ws.headers) or not valid_session(ws):
        await ws.close(code=4401)
        return
    await ws.accept()
    lang = ws.cookies.get(LANG_COOKIE)
    i18n.current.set(lang if lang in i18n.LANGS else "es")
    become = ws.query_params.get("become") or None
    first = None
    if not stepup_valid():
        # Toda terminal pide la contraseña maestra: el primer mensaje debe traerla
        try:
            first = json.loads(await asyncio.wait_for(ws.receive_text(), 300))
        except Exception:
            await ws.close()
            return
        if not await stepup(first.get("master_password", ""), f"terminal sudo su - {become}" if become else "terminal"):
            await ws.send_bytes(("\r\n\x1b[31m" + i18n._("Contraseña maestra incorrecta") + "\x1b[0m\r\n").encode())
            await ws.close()
            return
    await terminal.session(ws, vm_id, become, first)


# ---------- panel de ficheros (SFTP sobre la conexión de la terminal) ----------

def files_error(e):
    return JSONResponse({"error": str(e)}, status_code=400)


@app.get("/api/files/{sid}/list")
async def files_list(sid: str, path: str = ""):
    try:
        return await files.listdir(sid, path)
    except files.FilesError as e:
        return files_error(e)


@app.get("/api/files/{sid}/download")
async def files_download(sid: str, path: str):
    try:
        s, f = await files.open_for_download(sid, path)
    except files.FilesError as e:
        return files_error(e)
    db.audit("fichero_descargado", f"{s['vm_name']}: {path}")
    name = posixpath.basename(path) or "fichero"
    return StreamingResponse(files.iter_file(f), media_type="application/octet-stream",
                             headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}"})


@app.post("/api/files/{sid}/upload")
async def files_upload(request: Request, sid: str):
    if not stepup_valid():
        return {"stepup": True}
    form = await request.form()
    overwrite = bool(form.get("overwrite"))
    if overwrite and safety.enabled():
        return files_error("Modo seguro: no se permite sobrescribir ficheros")
    done = []
    try:
        for up in form.getlist("files"):
            s, dest = await files.upload(sid, form.get("path", "."), up.filename, up, overwrite)
            db.audit("fichero_subido", f"{s['vm_name']}: {dest}")
            done.append(dest)
    except files.FilesError as e:
        return JSONResponse({"error": str(e), "done": done}, status_code=400)
    return {"done": done}


@app.post("/api/files/{sid}/mkdir")
async def files_mkdir(request: Request, sid: str):
    if not stepup_valid():
        return {"stepup": True}
    path = (await request.json()).get("path", "")
    try:
        s = await files.mkdir(sid, path)
    except files.FilesError as e:
        return files_error(e)
    db.audit("carpeta_creada", f"{s['vm_name']}: {path}")
    return {"ok": True}


@app.post("/api/files/{sid}/delete")
async def files_delete(request: Request, sid: str):
    if safety.enabled():
        return files_error("Modo seguro: no se permite borrar ficheros (desactívalo en Ajustes si lo necesitas)")
    if not stepup_valid():
        return {"stepup": True}
    path = (await request.json()).get("path", "")
    try:
        s = await files.delete(sid, path)
    except files.FilesError as e:
        return files_error(e)
    db.audit("fichero_borrado", f"{s['vm_name']}: {path}")
    return {"ok": True}


# ---------- escaneos ----------

def runtime_auth(ids, body):
    """Comprueba qué servidores no tienen guardado usuario o contraseña.

    Si falta algo y el navegador aún no lo ha enviado, devuelve (None, lista de servidores a pedir).
    Si lo ha enviado ("auth"), devuelve ({vm_id: credenciales tecleadas}, None). Lo tecleado
    solo se guarda en memoria si se marca "recordar".
    """
    missing = []
    for vm in db.q(f"SELECT * FROM vms WHERE id IN ({','.join('?' * len(ids))})", ids) if ids else []:
        need = ssh.needs(vm)
        if need:
            missing.append({"id": vm["id"], "name": vm["name"], "host": vm["host"], "missing": need})
    if not missing:
        return {}, None
    auth = body.get("auth")
    if not auth:
        return None, missing
    typed = {k: (auth.get(k) or "") for k in ("username", "password", "sudo_password")}
    if auth.get("remember"):
        for m in missing:
            ssh.remember(m["id"], typed)
    return {m["id"]: typed for m in missing}, None


@app.post("/api/scan")
async def api_scan(request: Request):
    body = await request.json()
    if body.get("all"):
        ids = [r["id"] for r in db.q("SELECT id FROM vms")]
    elif "client" in body:
        # Uno o varios clientes ("" o "__none__" = sin cliente)
        clients = body["client"] if isinstance(body["client"], list) else [body["client"]]
        clients = ["" if c == NONE_VALUE else c for c in clients]
        ids = [r["id"] for r in db.q(f"SELECT id FROM vms WHERE {in_clause('COALESCE(client,\'\')', clients)}",
                                     clients)] if clients else []
    else:
        ids = [int(i) for i in body.get("ids", [])]
    exclude = {int(i) for i in body.get("exclude", [])}
    ids = [i for i in ids if i not in collector.running and i not in exclude]
    if exclude and not ids:
        return {"started": 0, "error": "Al omitir esos servidores no queda ninguno por escanear."}
    overrides, missing = runtime_auth(ids, body)
    if missing:
        return {"started": 0, "need_auth": missing}
    n = collector.start_scans(ids, overrides)
    if n:
        db.audit("escaneo", f"{n} servidores")
    return {"started": n}


@app.get("/api/activity")
async def api_activity():
    """Lo que está en curso ahora mismo: escaneos, ejecuciones remotas y terminales abiertas."""
    scans = []
    if collector.running:
        ids = list(collector.running)
        names = {r["id"]: r["name"] for r in db.q(f"SELECT id, name FROM vms WHERE id IN ({','.join('?' * len(ids))})", ids)}
        scans = [{"id": i, "name": names.get(i, str(i)), "state": s} for i, s in collector.running.items()]
    running_jobs = [dict(r) for r in db.q("""SELECT j.id, j.command, j.target_count,
        SUM(r.status NOT IN ('pendiente','ejecutando')) done FROM jobs j JOIN job_results r ON r.job_id=j.id
        WHERE j.finished_at IS NULL GROUP BY j.id ORDER BY j.id""")]
    terms = [{"vm_id": s["vm_id"], "vm_name": s["vm_name"], "since": s["since"], "become": s["become"]}
             for s in terminal.ACTIVE.values()]
    return {"scans": scans, "jobs": running_jobs, "terminals": terms}


@app.get("/api/scan/status")
async def api_scan_status():
    return {"running": {str(k): v for k, v in collector.running.items()}}


# ---------- credenciales ----------

@app.get("/credentials")
async def cred_list(request: Request):
    creds = db.q("""SELECT c.*, (SELECT COUNT(*) FROM vms WHERE credential_id=c.id) vm_count
                    FROM credentials c WHERE owner_vm_id IS NULL ORDER BY name""")
    own = db.q1("SELECT COUNT(*) n FROM credentials WHERE owner_vm_id IS NOT NULL")["n"]
    return render(request, "credentials.html", creds=creds, own_count=own)


@app.get("/credentials/new")
async def cred_new(request: Request):
    return render(request, "credential_form.html", cred=None)


@app.get("/credentials/{cred_id}/edit")
async def cred_edit_form(request: Request, cred_id: int):
    return render(request, "credential_form.html", cred=db.q1("SELECT * FROM credentials WHERE id=?", (cred_id,)))


async def _save_cred(request, cred_id=None):
    form = await request.form()
    name, username = form.get("name", "").strip(), form.get("username", "").strip()
    if not name or not username:
        return render(request, "credential_form.html", cred=None, error="Nombre y usuario son obligatorios.")
    fields = {"name": name, "username": username, "notes": form.get("notes", "").strip()}
    key_file = form.get("private_key_file")
    key_text = form.get("private_key", "").strip()
    if key_file is not None and getattr(key_file, "filename", ""):
        key_text = (await key_file.read()).decode("utf-8", "replace").strip()
    secrets_in = {"password_enc": form.get("password", ""), "private_key_enc": key_text,
                  "key_passphrase_enc": form.get("key_passphrase", ""),
                  "sudo_password_enc": form.get("sudo_password", "")}
    for col, val in secrets_in.items():
        if val or cred_id is None:
            fields[col] = vault.encrypt(val)
    for col in ("password_enc", "private_key_enc", "key_passphrase_enc", "sudo_password_enc"):
        if form.get(f"clear_{col}"):
            fields[col] = None
    try:
        if cred_id is None:
            fields["created_at"] = db.now()
            db.ex(f"INSERT INTO credentials({', '.join(fields)}) VALUES({', '.join('?' * len(fields))})",
                  tuple(fields.values()))
            db.audit("credencial_creada", name)
        else:
            db.ex(f"UPDATE credentials SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?",
                  (*fields.values(), cred_id))
            db.audit("credencial_editada", name)
    except sqlite3.IntegrityError:
        cred = db.q1("SELECT * FROM credentials WHERE id=?", (cred_id,)) if cred_id else None
        return render(request, "credential_form.html", cred=cred, error=f"Ya existe una credencial llamada '{name}'.")
    return redirect("/credentials")


@app.post("/credentials/new")
async def cred_create(request: Request):
    return await _save_cred(request)


@app.post("/credentials/{cred_id}/edit")
async def cred_edit(request: Request, cred_id: int):
    return await _save_cred(request, cred_id)


@app.post("/credentials/{cred_id}/delete")
async def cred_delete(request: Request, cred_id: int):
    c = db.q1("SELECT name FROM credentials WHERE id=?", (cred_id,))
    db.ex("DELETE FROM credentials WHERE id=?", (cred_id,))
    db.audit("credencial_eliminada", c["name"] if c else str(cred_id))
    return redirect("/credentials")


@app.post("/api/stepup")
async def api_stepup(request: Request):
    body = await request.json()
    if await stepup(body.get("password", ""), body.get("what", "")[:100]):
        return {"ok": True}
    return JSONResponse({"error": "Contraseña maestra incorrecta"}, status_code=403)


@app.post("/api/credentials/{cred_id}/reveal")
async def cred_reveal(cred_id: int):
    if not stepup_valid():
        return {"stepup": True}
    c = db.q1("SELECT * FROM credentials WHERE id=?", (cred_id,))
    if not c:
        return JSONResponse({"error": "no existe"}, status_code=404)
    db.audit("credencial_revelada", c["name"])
    return {"password": vault.decrypt(c["password_enc"]) or "", "sudo_password": vault.decrypt(c["sudo_password_enc"]) or ""}


# ---------- búsqueda ----------

def run_search(p):
    pkg = (p.get("pkg") or "").strip()
    if not pkg:
        return []
    where = ["p.name = ?" if p.get("exact") else "p.name LIKE ?"]
    args = [pkg if p.get("exact") else f"%{pkg}%"]
    # Familia y distribución son las del sitio donde está el paquete: la del contenedor o la del host
    multi_where(p, where, args, "v", {"os_family": "c.os_family, v.os_family", "os_name": "c.os_name, v.os_name"})
    if p.get("where") == "host":
        where.append("p.container IS NULL")
    elif p.get("where") == "containers":
        where.append("p.container IS NOT NULL")
    rows = db.q(f"""SELECT v.id vm_id, v.name vm_name, v.host, v.client, v.environment, v.last_ok_at,
                    COALESCE(c.os_name, v.os_name) os_name, COALESCE(c.os_version, v.os_version) os_version,
                    CASE WHEN p.source='sonda' THEN '' ELSE COALESCE(c.os_family, v.os_family) END os_family,
                    p.name, p.version, p.arch, p.source, p.container, c.image
                    FROM packages p JOIN vms v ON v.id=p.vm_id
                    LEFT JOIN containers c ON c.vm_id=p.vm_id AND c.name=p.container
                    WHERE {' AND '.join(where)}
                    ORDER BY v.client, v.name, p.container IS NOT NULL, p.container, p.name LIMIT 20000""", args)
    op, ver = p.get("op"), (p.get("ver") or "").strip()
    return [r for r in rows if versions.matches(r["version"], op, ver, r["os_family"])]


@app.get("/search")
async def search(request: Request):
    p = query_dict(request)
    results = run_search(p) if p.get("pkg") else None
    affected = len({r["vm_id"] for r in results}) if results else 0
    return render(request, "search.html", p=p, results=results, affected=affected, clients=distinct("client"),
                  envs=distinct("environment"), tags=all_tags(), qs=urlencode(p, doseq=True))


@app.get("/search.csv")
async def search_csv(request: Request):
    rows = run_search(query_dict(request))
    return csv_response("busqueda.csv", ["Servidor", "Host", "Cliente", "Entorno", "Dónde", "Imagen", "SO", "Versión SO",
                                          "Paquete", "Versión", "Arquitectura", "Origen", "Último escaneo correcto"],
                        [(r["vm_name"], r["host"], r["client"], r["environment"],
                          f"contenedor {r['container']}" if r["container"] else "host", r["image"] or "",
                          r["os_name"], r["os_version"], r["name"], r["version"], r["arch"], r["source"],
                          r["last_ok_at"]) for r in rows])


@app.get("/api/packages/suggest")
async def pkg_suggest(term: str = ""):
    if len(term) < 2:
        return []
    return [r["name"] for r in db.q("SELECT DISTINCT name FROM packages WHERE name LIKE ? ORDER BY name LIMIT 15",
                                    (f"{term}%",))]


# ---------- comandos masivos ----------

@app.get("/commands")
async def commands(request: Request):
    p = dict(request.query_params)
    vms = db.q("SELECT id, name, host, client, environment, os_family, last_scan_status, credential_id "
               "FROM vms ORDER BY client, name")
    recent = db.q("""SELECT j.*, SUM(r.status='ok') ok, SUM(r.status='fallo') fail, SUM(r.status='error') err,
                     SUM(r.status IN ('pendiente','ejecutando')) pend FROM jobs j
                     LEFT JOIN job_results r ON r.job_id=j.id GROUP BY j.id ORDER BY j.id DESC LIMIT 30""")
    preselect = {int(i) for i in p.get("ids", "").split(",") if i.isdigit()}
    seed_saved_commands()
    saved = [dict(r) for r in db.q("SELECT * FROM saved_commands ORDER BY name COLLATE NOCASE")]
    return render(request, "commands.html", vms=vms, recent=recent, preselect=preselect,
                  clients=distinct("client"), envs=distinct("environment"), command=p.get("command", ""),
                  tags=all_tags(), vm_tags=tags_by_vm(), saved=saved, saved_id=p.get("saved", ""))


# ---------- biblioteca de comandos ----------

SEED_COMMANDS = [
    ("Versión de un paquete", "Versión instalada del paquete indicado (RHEL y Debian/Ubuntu).",
     "rpm -q {{paquete}} 2>/dev/null || dpkg-query -W -f='${Package} ${Version}\\n' {{paquete}} 2>&1", 0),
    ("¿Servicio activo?", "Estado de un servicio systemd.", "systemctl is-active {{servicio}}; systemctl is-enabled {{servicio}}", 0),
    ("Puertos en escucha con proceso", "Qué proceso escucha en cada puerto (necesita sudo para ver todos).",
     "ss -tulpn", 1),
    ("Usuarios con shell", "Cuentas que pueden iniciar sesión.",
     "awk -F: '$7 !~ /(nologin|false)$/ {print $1\" \"$7}' /etc/passwd", 0),
    ("Últimos accesos", "Últimos 10 inicios de sesión.", "last -n 10 -a 2>/dev/null | head -n 12", 0),
    ("Espacio en disco", "Uso de los sistemas de ficheros.", "df -hP -x tmpfs -x devtmpfs", 0),
    ("¿Necesita reinicio?", "Comprueba si hay que reiniciar tras actualizar.",
     "if [ -f /var/run/reboot-required ]; then echo 'SI (reboot-required)'; "
     "elif command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r; else echo 'No se puede saber'; fi", 0),
    ("Actualizaciones de seguridad pendientes", "Según la caché local de dnf/apt (no descarga nada).",
     "if command -v dnf >/dev/null 2>&1; then dnf -q -C updateinfo list --security 2>/dev/null; "
     "else apt list --upgradable 2>/dev/null | grep -i security; fi", 0),
    ("Reglas sudo", "Contenido efectivo de sudoers.",
     "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -Ev '^\\s*(#|$)'", 1),
]


def seed_saved_commands():
    if db.get_setting("commands_seeded"):
        return
    for name, desc, cmd, sudo in SEED_COMMANDS:
        db.ex("INSERT INTO saved_commands(name, description, command, use_sudo, timeout_s, created_at) "
              "VALUES(?,?,?,?,?,?)", (name, desc, cmd, sudo, 60, db.now()))
    db.set_setting("commands_seeded", 1)


@app.post("/api/saved-commands")
async def saved_command_save(request: Request):
    b = await request.json()
    name, command = (b.get("name") or "").strip()[:100], (b.get("command") or "").strip()
    if not name or not command:
        return JSONResponse({"error": "Pon un nombre y un comando"}, status_code=400)
    vals = (name, (b.get("description") or "").strip()[:300], command, 1 if b.get("sudo") else 0,
            max(5, min(int(b.get("timeout") or 60), 3600)))
    if b.get("id"):
        db.ex("UPDATE saved_commands SET name=?, description=?, command=?, use_sudo=?, timeout_s=? WHERE id=?",
              (*vals, int(b["id"])))
        cmd_id = int(b["id"])
    else:
        cmd_id = db.ex("INSERT INTO saved_commands(name, description, command, use_sudo, timeout_s, created_at) "
                       "VALUES(?,?,?,?,?,?)", (*vals, db.now()))
    db.audit("comando_guardado", name)
    return {"id": cmd_id}


@app.post("/api/saved-commands/{cmd_id}/delete")
async def saved_command_delete(cmd_id: int):
    row = db.q1("SELECT name FROM saved_commands WHERE id=?", (cmd_id,))
    db.ex("DELETE FROM saved_commands WHERE id=?", (cmd_id,))
    db.audit("comando_eliminado", row["name"] if row else str(cmd_id))
    return {"ok": True}


# ---------- etiquetas ----------

@app.get("/tags")
async def tags_page(request: Request):
    catalogs = {}
    for kind, title in CATALOG_KINDS.items():
        counts = {r["v"]: r["n"] for r in db.q(f"SELECT {kind} v, COUNT(*) n FROM vms GROUP BY {kind}")}
        catalogs[kind] = {"title": title, "items": [(name, counts.get(name, 0)) for name in distinct(kind)],
                          "none": counts.get("", 0) + counts.get(None, 0)}
    return render(request, "tags.html", tags=all_tags(), colors=TAG_COLORS, catalogs=catalogs,
                  msg=request.query_params.get("msg"))


@app.post("/catalog/{kind}/new")
async def catalog_new(request: Request, kind: str):
    form = await request.form()
    if kind in CATALOG_KINDS:
        ensure_catalog(kind, form.get("name", "").strip()[:60])
    return redirect(f"/tags#{kind}")


@app.post("/catalog/{kind}/rename")
async def catalog_rename(request: Request, kind: str):
    form = await request.form()
    old, new = form.get("old", ""), form.get("name", "").strip()[:60]
    if kind not in CATALOG_KINDS or not new or new == old:
        return redirect(f"/tags#{kind}")
    with db.tx() as c:
        c.execute("DELETE FROM catalog WHERE kind=? AND name=?", (kind, old))
        c.execute("INSERT OR IGNORE INTO catalog(kind, name) VALUES(?,?)", (kind, new))
        n = c.execute(f"UPDATE vms SET {kind}=? WHERE {kind}=?", (new, old)).rowcount
    db.bump()
    db.audit("catalogo_renombrado", f"{kind}: {old} → {new} ({n} servidores)")
    return redirect("/tags?" + urlencode({"msg": f"'{old}' renombrado a '{new}' en {n} servidores"}) + f"#{kind}")


@app.post("/catalog/{kind}/delete")
async def catalog_delete(request: Request, kind: str):
    form = await request.form()
    name = form.get("name", "")
    if kind not in CATALOG_KINDS:
        return redirect("/tags#tags")
    with db.tx() as c:
        c.execute("DELETE FROM catalog WHERE kind=? AND name=?", (kind, name))
        n = c.execute(f"UPDATE vms SET {kind}='' WHERE {kind}=?", (name,)).rowcount
    db.bump()
    db.audit("catalogo_eliminado", f"{kind}: {name} ({n} servidores)")
    return redirect("/tags?" + urlencode({"msg": f"'{name}' eliminado; {n} servidores quedan sin {'cliente' if kind == 'client' else 'entorno'}"}) + f"#{kind}")


@app.post("/tags/new")
async def tag_create(request: Request):
    form = await request.form()
    if form.get("name", "").strip():
        tag_id = get_or_create_tag(form["name"])
        if form.get("color") in TAG_COLORS:
            db.ex("UPDATE tags SET color=? WHERE id=?", (form["color"], tag_id))
    return redirect("/tags#tags")


@app.post("/tags/{tag_id}/edit")
async def tag_edit(request: Request, tag_id: int):
    form = await request.form()
    name = form.get("name", "").strip()[:40]
    try:
        if name:
            db.ex("UPDATE tags SET name=? WHERE id=?", (name, tag_id))
        if form.get("color") in TAG_COLORS:
            db.ex("UPDATE tags SET color=? WHERE id=?", (form["color"], tag_id))
    except sqlite3.IntegrityError:
        pass
    db.bump()
    return redirect("/tags#tags")


@app.post("/tags/{tag_id}/delete")
async def tag_delete(request: Request, tag_id: int):
    db.ex("DELETE FROM tags WHERE id=?", (tag_id,))
    db.bump()
    return redirect("/tags#tags")


# ---------- gráficos ----------

def seed_charts():
    if db.get_setting("charts_seeded"):
        return
    for i, (title, kind, dim) in enumerate([("Sistemas operativos", "pie", "os"),
                                            ("Versiones de kernel", "bar", "kernel"),
                                            ("Antigüedad de la última actualización", "bar", "update_age")]):
        db.ex("INSERT INTO charts(title, kind, dimension, filters, position) VALUES(?,?,?,?,?)",
              (title, kind, dim, "{}", i))
    db.set_setting("charts_seeded", 1)


def chart_from_body(body):
    filters = {f: charts.as_list(body.get("filters", {}).get(f))[:100] for f in charts.FILTERS}
    return {"title": (body.get("title") or "Gráfico").strip()[:80],
            "kind": body.get("kind") if body.get("kind") in charts.KINDS else "pie",
            "dimension": body.get("dimension") if body.get("dimension") in charts.DIMENSIONS else "os",
            "package": (body.get("package") or "").strip()[:200],
            "filters": json.dumps({k: v for k, v in filters.items() if v})}


@app.get("/api/charts")
async def charts_list():
    out = []
    for c in db.q("SELECT * FROM charts ORDER BY position, id"):
        filters = json.loads(c["filters"] or "{}")
        data = charts.data(c, filters)
        data["labels"] = [i18n.translate_text(label) for label in data["labels"]]
        out.append({**dict(c), "title": i18n.translate_text(c["title"]), "filters": filters, "data": data})
    return {"version": db.data_version, "charts": out}


@app.get("/api/charts/version")
async def charts_version():
    return {"version": db.data_version}


@app.post("/api/charts")
async def chart_create(request: Request):
    c = chart_from_body(await request.json())
    pos = db.q1("SELECT COALESCE(MAX(position), 0) + 1 n FROM charts")["n"]
    db.ex("INSERT INTO charts(title, kind, dimension, package, filters, position) VALUES(?,?,?,?,?,?)",
          (*c.values(), pos))
    return {"ok": True}


@app.post("/api/charts/{chart_id}")
async def chart_update(request: Request, chart_id: int):
    body = await request.json()
    if body.get("delete"):
        db.ex("DELETE FROM charts WHERE id=?", (chart_id,))
    elif "move" in body:
        ids = [r["id"] for r in db.q("SELECT id FROM charts ORDER BY position, id")]
        if chart_id in ids:
            i = ids.index(chart_id)
            j = max(0, min(len(ids) - 1, i + int(body["move"])))
            ids[i], ids[j] = ids[j], ids[i]
            with db.tx() as tx:
                tx.executemany("UPDATE charts SET position=? WHERE id=?", [(n, cid) for n, cid in enumerate(ids)])
    else:
        c = chart_from_body(body)
        db.ex("UPDATE charts SET title=?, kind=?, dimension=?, package=?, filters=? WHERE id=?", (*c.values(), chart_id))
    return {"ok": True}


@app.post("/api/jobs")
async def create_job(request: Request):
    body = await request.json()
    ids = [int(i) for i in body.get("ids", [])]
    command = (body.get("command") or "").strip()
    if not ids or not command:
        return JSONResponse({"error": "Selecciona servidores y escribe un comando"}, status_code=400)
    timeout_s = max(5, min(int(body.get("timeout") or 60), 3600))
    if not stepup_valid():
        return {"stepup": True}
    dangers = safety.check(command) if safety.enabled() else []
    if dangers and body.get("confirm_danger") != safety.CONFIRM_WORD:
        return {"danger": dangers}
    if dangers:
        db.audit("comando_peligroso_confirmado", f"{'; '.join(dangers)} → {command}")
    exclude = {int(i) for i in body.get("exclude", [])}
    ids = [i for i in ids if i not in exclude]
    if not ids:
        return JSONResponse({"error": "Al omitir esos servidores no queda ninguno en el que ejecutar."}, status_code=400)
    overrides, missing = runtime_auth(ids, body)
    if missing:
        return {"need_auth": missing}
    return {"job_id": jobs.create_job(ids, command, bool(body.get("sudo")), timeout_s, overrides)}


@app.get("/jobs/{job_id}")
async def job_page(request: Request, job_id: int):
    job = db.q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not job:
        return redirect("/commands")
    return render(request, "job.html", job=job)


@app.get("/api/jobs/{job_id}")
async def job_api(job_id: int):
    job = db.q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    results = db.q("""SELECT r.*, v.client, v.host FROM job_results r LEFT JOIN vms v ON v.id=r.vm_id
                      WHERE job_id=? ORDER BY r.vm_name""", (job_id,))
    return {"finished": bool(job["finished_at"]), "results": [dict(r) for r in results]}


@app.get("/jobs/{job_id}/export.csv")
async def job_csv(job_id: int):
    rows = db.q("""SELECT r.*, v.client, v.host FROM job_results r LEFT JOIN vms v ON v.id=r.vm_id
                   WHERE job_id=? ORDER BY r.vm_name""", (job_id,))
    return csv_response(f"comando_{job_id}.csv", ["Servidor", "Host", "Cliente", "Estado", "Código salida", "Salida", "Errores"],
                        [(r["vm_name"], r["host"], r["client"], r["status"], r["exit_code"], r["stdout"], r["stderr"])
                         for r in rows])


# ---------- auditoría y ajustes ----------

@app.get("/audit")
async def audit_page(request: Request):
    verify = None
    if request.query_params.get("verify"):
        checked, keyed, problems = db.verify_audit(vault.audit_key())
        verify = {"checked": checked, "keyed": keyed, "problems": problems[:50], "total_problems": len(problems)}
        db.audit("auditoria_verificada", f"{checked} registros, {len(problems)} problemas")
    return render(request, "audit.html", rows=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 1000"),
                  verify=verify, syslog_target=db.get_setting("syslog_target", ""))


@app.get("/audit/export.jsonl")
async def audit_export():
    lines = [json.dumps({k: r[k] for k in ("id", "ts", "action", "detail", "prev_hash", "hash", "keyed")},
                        ensure_ascii=False) for r in db.q("SELECT * FROM audit ORDER BY id")]
    db.audit("auditoria_exportada", f"{len(lines)} registros")
    return file_response(("\n".join(lines) + "\n").encode(), f"auditoria_{datetime.now(db.TZ):%Y%m%d_%H%M}.jsonl",
                         "application/x-ndjson")


@app.post("/audit/syslog")
async def audit_syslog(request: Request):
    target = (await request.form()).get("target", "").strip()
    try:
        syslog.configure(target)
    except (ValueError, OSError) as e:
        return redirect("/audit?" + urlencode({"error": f"Destino syslog no válido: {e}"}))
    db.set_setting("syslog_target", target)
    db.audit("syslog_configurado", target or "desactivado")
    return redirect("/audit")


@app.get("/scan-info")
async def scan_info(request: Request):
    probes = collector.active_probes()
    return render(request, "scan_info.html", script=collector.host_script(probes).strip(),
                  container_script=collector.container_script(probes).strip())


@app.get("/settings")
async def settings_page(request: Request):
    return render(request, "settings.html", s={k: db.get_setting(k, d) for k, d in DEFAULT_SETTINGS.items()},
                  safe_mode=safety.enabled(), safe_rules=safety.RULES, p=prefs(), accents=ACCENTS,
                  probes=db.q("SELECT * FROM probes ORDER BY name"),
                  hostkey_policy=db.get_setting("hostkey_policy", "confirm"),
                  known_hosts_lines=len([l for l in db.get_setting("known_hosts", "").splitlines()
                                         if l.strip() and not l.startswith("#")]),
                  date_formats=DATE_FORMATS, timezones=TIMEZONES,
                  msg=request.query_params.get("msg"), error=request.query_params.get("error"))


BIN_RE = re.compile(r"^[\w./+\-]{1,120}$")


def probe_problem(name, binary, command, regex):
    if not name or not binary or not command or not regex:
        return f"Sonda '{name or '?'}': rellena nombre, ejecutable, comando y expresión"
    if not BIN_RE.match(binary):
        return f"Sonda '{name}': el ejecutable solo puede tener letras, números, / . _ + -"
    try:
        if re.compile(regex).groups < 1:
            return f"Sonda '{name}': la expresión necesita un grupo ( ) con la versión"
    except re.error as e:
        return f"Sonda '{name}': expresión regular no válida ({e})"
    if safety.check(command):
        return f"Sonda '{name}': el comando parece peligroso; las sondas solo deben leer versiones"
    return None


@app.post("/settings/probes")
async def settings_probes(request: Request):
    form = await request.form()
    errors = []
    for p in db.q("SELECT id FROM probes"):
        pid = p["id"]
        vals = [form.get(f"{k}_{pid}", "").strip() for k in ("name", "bin", "command", "regex")]
        problem = probe_problem(*vals)
        if problem:
            errors.append(problem)
            continue
        db.ex("UPDATE probes SET name=?, bin=?, command=?, regex=?, enabled=? WHERE id=?",
              (*vals, 1 if form.get(f"enabled_{pid}") else 0, pid))
    new = [form.get(f"new_{k}", "").strip() for k in ("name", "bin", "command", "regex")]
    if any(new):
        problem = probe_problem(*new)
        if problem:
            errors.append(problem)
        else:
            db.ex("INSERT INTO probes(name, bin, command, regex) VALUES(?,?,?,?)", new)
    db.audit("sondas", "Detección de versiones modificada")
    q = {"error": " · ".join(errors)} if errors else {"msg": "Ajustes guardados"}
    return redirect("/settings?" + urlencode(q) + "#sondas")


@app.post("/settings/probes/{pid}/delete")
async def settings_probe_delete(pid: int):
    p = db.q1("SELECT name FROM probes WHERE id=?", (pid,))
    if p:
        db.ex("DELETE FROM probes WHERE id=?", (pid,))
        db.audit("sondas", f"Detección de versiones eliminada: {p['name']}")
    return redirect("/settings?" + urlencode({"msg": "Detección eliminada"}) + "#sondas")


@app.post("/settings/safe-mode")
async def settings_safe_mode(request: Request):
    form = await request.form()
    on = "1" if form.get("safe_mode") else "0"
    db.set_setting("safe_mode", on)
    db.audit("modo_seguro", "activado" if on == "1" else "DESACTIVADO")
    return redirect("/settings?" + urlencode({"msg": "Ajustes guardados"}) + "#seguro")


@app.post("/settings/appearance")
async def settings_appearance(request: Request):
    form = await request.form()
    choices = {"theme": ("auto", "light", "dark"), "accent": tuple(ACCENTS), "density": ("normal", "compact"),
               "date_format": tuple(DATE_FORMATS), "timezone": tuple(TIMEZONES)}
    for key, allowed in choices.items():
        if form.get(key) in allowed:
            db.set_setting(f"pref_{key}", form[key])
    cols = [c for c in form.get("vm_columns", "").split(",") if c in VM_COLUMNS]
    db.set_setting("pref_vm_columns", json.dumps(cols or DEFAULT_VM_COLUMNS))
    apply_timezone()
    return redirect("/settings?" + urlencode({"msg": "Ajustes guardados"}) + "#apariencia")


DEFAULT_SETTINGS = {"scan_concurrency": 15, "command_concurrency": 20, "auto_scan_hours": 0, "auto_lock_minutes": 15,
                    "retention_jobs_days": 90, "retention_history_days": 365, "retention_audit_days": 730}


@app.post("/settings")
async def settings_save(request: Request):
    form = await request.form()
    limits = {"scan_concurrency": (1, 100), "command_concurrency": (1, 100), "auto_scan_hours": (0, 720),
              "auto_lock_minutes": (0, 1440), "retention_jobs_days": (1, 3650),
              "retention_history_days": (1, 3650), "retention_audit_days": (30, 3650)}
    for key, (lo, hi) in limits.items():
        try:
            db.set_setting(key, max(lo, min(hi, int(form.get(key, DEFAULT_SETTINGS[key])))))
        except ValueError:
            pass
    db.audit("ajustes", "Ajustes modificados")
    return redirect("/settings?" + urlencode({"msg": "Ajustes guardados"}))


@app.post("/settings/password")
async def settings_password(request: Request):
    form = await request.form()
    new = form.get("new", "")
    if len(new) < 10 or new != form.get("new2"):
        return redirect("/settings?" + urlencode({"error": "La nueva contraseña debe tener 10+ caracteres y coincidir"}))
    if not await check_master(form.get("old", "")):
        return redirect("/settings?" + urlencode({"error": "La contraseña actual no es correcta"}))
    salt = os.urandom(16)
    vault.rekey(await asyncio.to_thread(derive_key, new, salt), salt)
    db.audit("password_maestra", "Contraseña maestra cambiada")
    return redirect("/settings?" + urlencode({"msg": "Contraseña maestra cambiada"}))


# ---------- copias de seguridad ----------

def backup_page(request, **ctx):
    counts = {k: db.q1(f"SELECT COUNT(*) n FROM {t}")["n"] for k, t in
              (("vms", "vms"), ("commands", "saved_commands"), ("charts", "charts"), ("tags", "tags"))}
    counts["credentials"] = db.q1("SELECT COUNT(*) n FROM credentials WHERE owner_vm_id IS NULL")["n"]
    counts["catalog"] = db.q1("SELECT COUNT(*) n FROM catalog")["n"]
    return render(request, "backup.html", sections=backup.SECTIONS, counts=counts, **ctx)


@app.get("/backup")
async def backup_get(request: Request):
    return backup_page(request)


@app.get("/settings/backup")
async def backup_db():
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    dest = sqlite3.connect(tmp.name)
    db.conn().backup(dest)
    dest.close()
    db.audit("copia_seguridad", "Copia exacta (.db) descargada")
    name = f"lcc_copia_exacta_{datetime.now(db.TZ):%Y%m%d_%H%M}.db"
    return FileResponse(tmp.name, filename=name, background=BackgroundTask(os.unlink, tmp.name))


def collect_export(sections):
    tag_names = {t["id"]: t["name"] for t in db.q("SELECT id, name FROM tags")}
    data = {"format": backup.FORMAT, "version": 1, "created_at": db.now(), "sections": sorted(sections)}
    if "organization" in sections:
        data["clients"] = [r["name"] for r in db.q("SELECT name FROM catalog WHERE kind='client' ORDER BY name")]
        data["environments"] = [r["name"] for r in db.q("SELECT name FROM catalog WHERE kind='environment' ORDER BY name")]
        data["tags"] = [{"name": t["name"], "color": t["color"]} for t in db.q("SELECT * FROM tags ORDER BY name")]
    if "credentials" in sections:
        data["credentials"] = [{
            "name": c["name"], "username": c["username"], "notes": c["notes"],
            "password": vault.decrypt(c["password_enc"]), "sudo_password": vault.decrypt(c["sudo_password_enc"]),
            "private_key": vault.decrypt(c["private_key_enc"]), "key_passphrase": vault.decrypt(c["key_passphrase_enc"]),
        } for c in db.q("SELECT * FROM credentials WHERE owner_vm_id IS NULL ORDER BY name")]
    if "vms" in sections:
        tmap = tags_by_vm()
        data["vms"] = []
        for v in db.q("""SELECT vms.*, c.name cred_name, c.owner_vm_id cred_own, c.username cred_user,
                         c.password_enc, c.sudo_password_enc FROM vms LEFT JOIN credentials c ON c.id=vms.credential_id
                         ORDER BY vms.client, vms.name"""):
            item = {k: v[k] for k in ("name", "host", "port", "client", "environment", "notes", "host_key")}
            item["tags"] = [t["name"] for t in tmap.get(v["id"], [])]
            if v["cred_own"]:
                item["own_credential"] = {"username": v["cred_user"], "password": vault.decrypt(v["password_enc"]),
                                          "sudo_password": vault.decrypt(v["sudo_password_enc"])}
            elif v["cred_name"]:
                item["credential"] = v["cred_name"]
            data["vms"].append(item)
    if "commands" in sections:
        data["commands"] = [{k: r[k] for k in ("name", "description", "command", "use_sudo", "timeout_s")}
                            for r in db.q("SELECT * FROM saved_commands ORDER BY name")]
    if "charts" in sections:
        data["charts"] = []
        for r in db.q("SELECT * FROM charts ORDER BY position, id"):
            filters = json.loads(r["filters"] or "{}")
            if filters.get("tag"):
                filters["tag"] = tag_names.get(int(filters["tag"]), "")
            data["charts"].append({k: r[k] for k in ("title", "kind", "dimension", "package")} | {"filters": filters})
    if "settings" in sections:
        data["settings"] = {k: db.get_setting(k, d) for k, d in DEFAULT_SETTINGS.items()}
    return data


def apply_import(data, update):
    """Fusiona una exportación con lo que ya hay. Devuelve un resumen por sección."""
    summary = {}

    def count(section, key):
        summary.setdefault(section, {"añadidos": 0, "actualizados": 0, "sin cambios": 0})[key] += 1

    for name in data.get("clients", []):
        ensure_catalog("client", name)
    for name in data.get("environments", []):
        ensure_catalog("environment", name)
    for t in data.get("tags", []):
        exists = db.q1("SELECT id FROM tags WHERE name=?", (t["name"],))
        tag_id = get_or_create_tag(t["name"])
        if t.get("color") in TAG_COLORS and (update or not exists):
            db.ex("UPDATE tags SET color=? WHERE id=?", (t["color"], tag_id))
        count("Etiquetas", "añadidos" if not exists else "actualizados" if update else "sin cambios")
    if "clients" in data or "environments" in data:
        summary["Clientes y entornos"] = {"total": len(data.get("clients", [])) + len(data.get("environments", []))}

    for c in data.get("credentials", []):
        row = db.q1("SELECT id FROM credentials WHERE name=? AND owner_vm_id IS NULL", (c["name"],))
        if row and not update:
            count("Credenciales compartidas", "sin cambios")
            continue
        fields = {"username": c["username"], "notes": c.get("notes"),
                  "password_enc": vault.encrypt(c.get("password")), "sudo_password_enc": vault.encrypt(c.get("sudo_password")),
                  "private_key_enc": vault.encrypt(c.get("private_key")),
                  "key_passphrase_enc": vault.encrypt(c.get("key_passphrase"))}
        if row:
            db.ex(f"UPDATE credentials SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", (*fields.values(), row["id"]))
            count("Credenciales compartidas", "actualizados")
        else:
            fields.update(name=c["name"], created_at=db.now())
            db.ex(f"INSERT INTO credentials({', '.join(fields)}) VALUES({', '.join('?' * len(fields))})",
                  tuple(fields.values()))
            count("Credenciales compartidas", "añadidos")

    shared = {r["name"].lower(): r["id"] for r in shared_creds()}
    for v in data.get("vms", []):
        ensure_catalog("client", v.get("client"))
        ensure_catalog("environment", v.get("environment"))
        dup = find_duplicate(v.get("client"), v["host"], v.get("port") or 22)
        if dup and not update:
            count("Servidores", "sin cambios")
            continue
        fields = {"name": v["name"], "client": v.get("client") or "", "environment": v.get("environment") or "",
                  "notes": v.get("notes") or ""}
        if dup:
            vm_id = dup["id"]
            db.ex(f"UPDATE vms SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?", (*fields.values(), vm_id))
            count("Servidores", "actualizados")
        else:
            fields.update(host=v["host"], port=v.get("port") or 22, host_key=v.get("host_key"), created_at=db.now())
            vm_id = db.ex(f"INSERT INTO vms({', '.join(fields)}) VALUES({', '.join('?' * len(fields))})",
                          tuple(fields.values()))
            count("Servidores", "añadidos")
        own = v.get("own_credential")
        if own and own.get("username"):
            set_own_credential(vm_id, own["username"], own.get("password") or "", own.get("sudo_password") or "")
        elif v.get("credential") and v["credential"].lower() in shared:
            db.ex("UPDATE vms SET credential_id=? WHERE id=?", (shared[v["credential"].lower()], vm_id))
            db.ex("DELETE FROM credentials WHERE owner_vm_id=?", (vm_id,))
        if v.get("tags"):
            current = [t["id"] for t in tags_by_vm().get(vm_id, [])]
            set_vm_tags(vm_id, current, ",".join(v["tags"]))

    for cmd in data.get("commands", []):
        row = db.q1("SELECT id FROM saved_commands WHERE name=?", (cmd["name"],))
        vals = (cmd["name"], cmd.get("description"), cmd["command"], int(cmd.get("use_sudo") or 0),
                int(cmd.get("timeout_s") or 60))
        if row and not update:
            count("Comandos guardados", "sin cambios")
        elif row:
            db.ex("UPDATE saved_commands SET name=?, description=?, command=?, use_sudo=?, timeout_s=? WHERE id=?",
                  (*vals, row["id"]))
            count("Comandos guardados", "actualizados")
        else:
            db.ex("INSERT INTO saved_commands(name, description, command, use_sudo, timeout_s, created_at) "
                  "VALUES(?,?,?,?,?,?)", (*vals, db.now()))
            count("Comandos guardados", "añadidos")
    if "commands" in data:
        db.set_setting("commands_seeded", 1)

    for ch in data.get("charts", []):
        filters = dict(ch.get("filters") or {})
        if filters.get("tag"):
            filters["tag"] = str(get_or_create_tag(filters["tag"]))
        if db.q1("SELECT id FROM charts WHERE title=? AND dimension=?", (ch["title"], ch["dimension"])):
            count("Gráficos", "sin cambios")
            continue
        c = chart_from_body({**ch, "filters": filters})
        pos = db.q1("SELECT COALESCE(MAX(position), 0) + 1 n FROM charts")["n"]
        db.ex("INSERT INTO charts(title, kind, dimension, package, filters, position) VALUES(?,?,?,?,?,?)",
              (*c.values(), pos))
        count("Gráficos", "añadidos")
    if "charts" in data:
        db.set_setting("charts_seeded", 1)

    for k, val in (data.get("settings") or {}).items():
        if k in DEFAULT_SETTINGS:
            db.set_setting(k, val)
    if data.get("settings"):
        summary["Ajustes"] = {"aplicados": len(data["settings"])}
    db.bump()
    return summary


@app.post("/backup/export")
async def backup_export(request: Request):
    form = await request.form()
    sections = [s for s in backup.SECTIONS if form.get(f"s_{s}")]
    pw, pw2 = form.get("file_password", ""), form.get("file_password2", "")
    if not sections:
        return backup_page(request, error="Marca al menos una cosa para exportar.")
    if len(pw) < 10 or pw != pw2:
        return backup_page(request, error="La contraseña del fichero debe tener 10+ caracteres y coincidir.")
    if not await check_master(form.get("master_password", "")):
        return backup_page(request, error="Contraseña maestra incorrecta: no se ha exportado nada.")
    data = collect_export(sections)
    blob = await asyncio.to_thread(backup.encrypt, data, pw)
    db.audit("exportacion_completa", ", ".join(sections))
    return file_response(blob, f"lcc_export_{datetime.now(db.TZ):%Y%m%d_%H%M}.lcc", "application/octet-stream")


@app.post("/backup/import")
async def backup_import(request: Request):
    form = await request.form()
    upload = form.get("file")
    if not await check_master(form.get("master_password", "")):
        return backup_page(request, error="Contraseña maestra incorrecta: no se ha importado nada.")
    try:
        data = await asyncio.to_thread(backup.decrypt, await upload.read(), form.get("file_password", ""))
    except backup.BackupError as e:
        return backup_page(request, error=str(e))
    except Exception as e:
        return backup_page(request, error=f"No se pudo leer el fichero: {e}")
    summary = apply_import(data, form.get("mode") == "update")
    db.audit("importacion_completa", f"{getattr(upload, 'filename', '')}: {summary}")
    return backup_page(request, summary=summary, imported_at=data.get("created_at"))


@app.post("/backup/restore-db")
async def backup_restore_db(request: Request):
    form = await request.form()
    raw = await form["file"].read()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.write(raw)
    tmp.close()
    try:
        check = sqlite3.connect(tmp.name)
        ok = check.execute("SELECT value FROM settings WHERE key='vault_salt'").fetchone()
        check.close()
        if not ok:
            raise ValueError
    except Exception:
        os.unlink(tmp.name)
        return backup_page(request, error="Ese fichero no es una copia exacta (.db) de esta aplicación.")
    # Guarda la base de datos actual por si acaso y la sustituye por la copia
    safety = os.path.join(db.DATA_DIR, f"antes_de_restaurar_{datetime.now(db.TZ):%Y%m%d_%H%M%S}.db")
    dest = sqlite3.connect(safety)
    db.conn().backup(dest)
    dest.close()
    db.close()
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db.DB_PATH + suffix):
            os.unlink(db.DB_PATH + suffix)
    shutil.move(tmp.name, db.DB_PATH)
    sessions.clear()
    vault.lock()
    ssh.session_auth.clear()
    db.audit("restauracion", f"Copia exacta restaurada; la anterior se guardó como {os.path.basename(safety)}")
    resp = redirect("/login")
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---------- escaneo automático ----------

async def auto_scan_loop():
    while True:
        await asyncio.sleep(60)
        try:
            hours = int(db.get_setting("auto_scan_hours", 0))
            if hours <= 0 or not vault.unlocked:
                continue
            # Los servidores que piden credenciales al conectar solo se escanean solas si están "recordadas"
            due = [r for r in db.q("""SELECT * FROM vms WHERE
                                      last_scan_at IS NULL OR last_scan_at < datetime('now', 'localtime', ?)""",
                                   (f"-{hours} hours",)) if not ssh.needs(r)]
            if collector.start_scans([r["id"] for r in due]):
                db.audit("escaneo_automatico", f"{len(due)} servidores")
        except Exception:
            pass


def apply_retention():
    """Borra el historial antiguo según Ajustes. El inventario actual nunca se borra."""
    days = {k: int(db.get_setting(k, d)) for k, d in DEFAULT_SETTINGS.items() if k.startswith("retention_")}
    deleted = 0
    with db.tx() as c:
        cutoff = f"-{days['retention_jobs_days']} days"
        deleted += c.execute("DELETE FROM jobs WHERE created_at < datetime('now','localtime',?)", (cutoff,)).rowcount
        cutoff = f"-{days['retention_history_days']} days"
        deleted += c.execute("DELETE FROM scan_history WHERE finished_at < datetime('now','localtime',?)",
                             (cutoff,)).rowcount
        deleted += c.execute("DELETE FROM audit WHERE ts < datetime('now','localtime',?)",
                             (f"-{days['retention_audit_days']} days",)).rowcount
    db.conn().execute("PRAGMA optimize")
    if deleted > 5000:
        db.conn().execute("VACUUM")
    return deleted


def maybe_auto_lock():
    minutes = int(db.get_setting("auto_lock_minutes", DEFAULT_SETTINGS["auto_lock_minutes"]))
    if minutes > 0 and vault.unlocked and time.time() - last_activity > minutes * 60 and not busy():
        lock_all(f"Bloqueo automático tras {minutes} min sin actividad")
        return True
    return False


async def maintenance_loop():
    """Cada minuto: bloqueo por inactividad. Una vez al día: limpieza del historial antiguo."""
    last_cleanup = 0.0
    while True:
        await asyncio.sleep(60)
        try:
            maybe_auto_lock()
            if vault.initialized and time.time() - last_cleanup > 86400:
                last_cleanup = time.time()
                n = apply_retention()
                if n:
                    db.audit("limpieza_historial", f"{n} registros antiguos borrados")
        except Exception:
            pass


_background = set()


def startup():
    db.conn()
    apply_timezone()
    try:
        syslog.configure(db.get_setting("syslog_target", ""))
    except (ValueError, OSError):
        pass
    collector.seed_probes()
    # Ejecuciones que quedaron a medias por un reinicio: se cierran para que no figuren "en curso" siempre
    db.ex("UPDATE job_results SET status='error', stderr='Interrumpido por un reinicio de la aplicación' "
          "WHERE status IN ('pendiente','ejecutando')")
    db.ex("UPDATE jobs SET finished_at=? WHERE finished_at IS NULL", (db.now(),))
    for loop in (auto_scan_loop, maintenance_loop):
        _background.add(asyncio.create_task(loop()))


@asynccontextmanager
async def lifespan(_app):
    startup()
    yield
    for task in _background:
        task.cancel()


app.router.lifespan_context = lifespan
