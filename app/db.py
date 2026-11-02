"""Base de datos SQLite. Todo el acceso ocurre en el hilo del bucle asyncio."""
import hashlib
import hmac
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from zoneinfo import ZoneInfo

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.path.join(DATA_DIR, "inventario.db")
TZ = ZoneInfo(os.environ.get("TZ", "Europe/Madrid"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    password_enc TEXT,
    private_key_enc TEXT,
    key_passphrase_enc TEXT,
    sudo_password_enc TEXT,
    notes TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS vms (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    client TEXT,
    environment TEXT,
    tags TEXT,
    notes TEXT,
    credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
    host_key TEXT,
    created_at TEXT,
    hostname TEXT,
    os_id TEXT,
    os_name TEXT,
    os_version TEXT,
    os_family TEXT,
    kernel TEXT,
    arch TEXT,
    uptime_s INTEGER,
    reboot_required INTEGER,
    pending_updates INTEGER,
    pending_security INTEGER,
    last_pkg_update TEXT,
    pkg_count INTEGER,
    last_scan_at TEXT,
    last_ok_at TEXT,
    last_scan_status TEXT NOT NULL DEFAULT 'never',
    last_scan_error TEXT
);

CREATE TABLE IF NOT EXISTS packages (
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    arch TEXT,
    source TEXT
);
CREATE INDEX IF NOT EXISTS ix_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS ix_packages_vm ON packages(vm_id);

CREATE TABLE IF NOT EXISTS ports (
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    proto TEXT,
    address TEXT,
    port INTEGER
);

CREATE TABLE IF NOT EXISTS services (
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY,
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    started_at TEXT,
    finished_at TEXT,
    status TEXT,
    error TEXT,
    pkg_count INTEGER,
    added INTEGER,
    removed INTEGER,
    changed INTEGER
);

CREATE TABLE IF NOT EXISTS package_changes (
    scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    name TEXT,
    old_version TEXT,
    new_version TEXT,
    change TEXT
);
CREATE INDEX IF NOT EXISTS ix_changes_vm ON package_changes(vm_id);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    command TEXT NOT NULL,
    use_sudo INTEGER NOT NULL DEFAULT 0,
    timeout_s INTEGER,
    created_at TEXT,
    finished_at TEXT,
    target_count INTEGER
);

CREATE TABLE IF NOT EXISTS job_results (
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    vm_id INTEGER REFERENCES vms(id) ON DELETE SET NULL,
    vm_name TEXT,
    status TEXT,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_job_results_job ON job_results(job_id);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    color TEXT
);

CREATE TABLE IF NOT EXISTS vm_tags (
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (vm_id, tag_id)
);

CREATE TABLE IF NOT EXISTS containers (
    vm_id INTEGER NOT NULL REFERENCES vms(id) ON DELETE CASCADE,
    runtime TEXT,
    cid TEXT,
    name TEXT,
    image TEXT,
    state TEXT,
    status TEXT,
    ports TEXT,
    os_name TEXT,
    os_version TEXT,
    os_family TEXT,
    pkg_count INTEGER,
    error TEXT
);
CREATE INDEX IF NOT EXISTS ix_containers_vm ON containers(vm_id);

CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    bin TEXT NOT NULL,
    command TEXT NOT NULL,
    regex TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS catalog (
    kind TEXT NOT NULL,
    name TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (kind, name)
);

CREATE TABLE IF NOT EXISTS saved_commands (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    command TEXT NOT NULL,
    use_sudo INTEGER NOT NULL DEFAULT 0,
    timeout_s INTEGER NOT NULL DEFAULT 60,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS charts (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    kind TEXT NOT NULL,
    dimension TEXT NOT NULL,
    package TEXT,
    filters TEXT,
    position INTEGER
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    action TEXT,
    detail TEXT
);
"""

_conn = None


def conn():
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.executescript(SCHEMA)
        _migrate(_conn)
    return _conn


def _add_columns(c, table, columns):
    existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
    for name, decl in columns:
        if name not in existing:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _migrate(c):
    # Credencial propia de un solo servidor (no aparece en la lista de credenciales compartidas)
    _add_columns(c, "credentials", [("owner_vm_id", "INTEGER")])
    # packages.container: NULL = paquete del host; si no, nombre del contenedor donde está
    _add_columns(c, "packages", [("container", "TEXT")])
    _add_columns(c, "package_changes", [("container", "TEXT")])
    _add_columns(c, "vms", [("container_count", "INTEGER"), ("containers_error", "TEXT"),
                            ("pending_host_key", "TEXT"), ("jump_vm_id", "INTEGER")])
    _add_columns(c, "audit", [("prev_hash", "TEXT"), ("hash", "TEXT"), ("keyed", "INTEGER")])
    if not c.execute("SELECT 1 FROM settings WHERE key='tags_migrated'").fetchone():
        # Las etiquetas antes eran texto libre separado por comas
        for vm in c.execute("SELECT id, tags FROM vms WHERE tags IS NOT NULL AND tags<>''").fetchall():
            for name in {t.strip() for t in vm["tags"].split(",") if t.strip()}:
                c.execute("INSERT OR IGNORE INTO tags(name) VALUES(?)", (name,))
                tag_id = c.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()["id"]
                c.execute("INSERT OR IGNORE INTO vm_tags(vm_id, tag_id) VALUES(?,?)", (vm["id"], tag_id))
        c.execute("INSERT INTO settings(key, value) VALUES('tags_migrated', '1')")
    if not c.execute("SELECT 1 FROM settings WHERE key='catalog_migrated'").fetchone():
        # Clientes y entornos pasan a ser listas gestionadas (antes eran texto libre)
        for kind in ("client", "environment"):
            c.execute(f"INSERT OR IGNORE INTO catalog(kind, name) SELECT DISTINCT '{kind}', {kind} FROM vms "
                      f"WHERE {kind} IS NOT NULL AND {kind}<>''")
        for env in ("PRO", "PRE", "DEV"):
            c.execute("INSERT OR IGNORE INTO catalog(kind, name) VALUES('environment', ?)", (env,))
        c.execute("INSERT INTO settings(key, value) VALUES('catalog_migrated', '1')")
    if not c.execute("SELECT 1 FROM settings WHERE key='mojibake_fixed'").fetchone():
        # Una versión guardó algunos textos con las tildes mal codificadas ("VersiÃ³n")
        for table, cols in (("saved_commands", ("name", "description", "command")), ("charts", ("title",)),
                            ("audit", ("action", "detail"))):
            for row in c.execute(f"SELECT rowid AS rid, {', '.join(cols)} FROM {table}").fetchall():
                fixed = [fix_mojibake(row[col]) for col in cols]
                if fixed != [row[col] for col in cols]:
                    c.execute(f"UPDATE {table} SET {', '.join(f'{col}=?' for col in cols)} WHERE rowid=?",
                              (*fixed, row["rid"]))
        c.execute("INSERT INTO settings(key, value) VALUES('mojibake_fixed', '1')")
    # Siempre al final (después de cualquier corrección de textos): los registros de auditoría anteriores a
    # la auditoría encadenada se encadenan sin firma para empezar desde aquí.
    if c.execute("SELECT 1 FROM audit WHERE hash IS NULL LIMIT 1").fetchone():
        prev = ""
        for r in c.execute("SELECT * FROM audit ORDER BY id").fetchall():
            if r["hash"] is None:
                h = _audit_hash(prev, r["ts"], r["action"], r["detail"] or "", None)
                c.execute("UPDATE audit SET prev_hash=?, hash=?, keyed=0 WHERE id=?", (prev, h, r["id"]))
                prev = h
            else:
                prev = r["hash"]


def fix_mojibake(text):
    if not text or "Ã" not in text and "Â" not in text and "â" not in text:
        return text
    try:
        return b"".join(ch.encode("cp1252") if ord(ch) > 255 else bytes([ord(ch)]) for ch in text).decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


# Contador que cambia cada vez que cambian los datos del inventario (para refrescar gráficos)
data_version = 0


def bump():
    global data_version
    data_version += 1


def close():
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


def q(sql, args=()):
    return conn().execute(sql, args).fetchall()


def q1(sql, args=()):
    return conn().execute(sql, args).fetchone()


def ex(sql, args=()):
    return conn().execute(sql, args).lastrowid


@contextmanager
def tx():
    c = conn()
    c.execute("BEGIN")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def now():
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")


def from_epoch(ts):
    return datetime.fromtimestamp(int(ts), TZ).strftime("%Y-%m-%d %H:%M:%S")


def get_setting(key, default=None):
    row = q1("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key, value):
    ex("INSERT INTO settings(key, value) VALUES(?, ?) "
       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


# ---------- auditoría encadenada ----------
# Cada registro guarda el hash del anterior. Con la aplicación desbloqueada el hash es un HMAC con una
# clave derivada de la contraseña maestra: quien edite la base de datos sin ella no puede recalcularlo.
audit_key_fn = lambda: None   # lo configura main.py (vault.subkey("audit"))
audit_listeners = []          # p. ej. el envío por syslog


def _audit_hash(prev, ts, action, detail, key):
    payload = f"{prev}|{ts}|{action}|{detail}".encode()
    if key:
        return hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def audit(action, detail=""):
    ts = now()
    last = q1("SELECT hash FROM audit ORDER BY id DESC LIMIT 1")
    prev = (last["hash"] if last else "") or ""
    key = audit_key_fn()
    h = _audit_hash(prev, ts, action, detail or "", key)
    ex("INSERT INTO audit(ts, action, detail, prev_hash, hash, keyed) VALUES(?,?,?,?,?,?)",
       (ts, action, detail, prev, h, 1 if key else 0))
    for listener in audit_listeners:
        try:
            listener(ts, action, detail, h)
        except Exception:
            pass


def verify_audit(key):
    """Comprueba la cadena. Devuelve (registros revisados, firmados, lista de problemas)."""
    problems, prev, checked, keyed = [], None, 0, 0
    for r in q("SELECT * FROM audit ORDER BY id"):
        checked += 1
        if prev is not None and (r["prev_hash"] or "") != prev:
            problems.append((r["id"], "Falta un registro anterior o se ha modificado (cadena rota)"))
        if r["keyed"]:
            keyed += 1
            if not key:
                problems.append((r["id"], "Registro firmado: desbloquea la aplicación para verificarlo"))
            elif not hmac.compare_digest(_audit_hash(r["prev_hash"] or "", r["ts"], r["action"], r["detail"] or "", key),
                                         r["hash"] or ""):
                problems.append((r["id"], "La firma no coincide: el registro se ha modificado"))
        elif _audit_hash(r["prev_hash"] or "", r["ts"], r["action"], r["detail"] or "", None) != (r["hash"] or ""):
            problems.append((r["id"], "El hash no coincide: el registro se ha modificado"))
        prev = r["hash"] or ""
    return checked, keyed, problems
