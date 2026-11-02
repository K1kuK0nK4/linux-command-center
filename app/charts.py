"""Gráficos personalizables: agrupan los servidores por la dimensión elegida."""
from collections import Counter
from datetime import datetime
from urllib.parse import urlencode

from . import db

DIMENSIONS = {
    "os": "Sistema operativo + versión",
    "os_name": "Distribución",
    "os_version": "Versión del SO",
    "os_family": "Familia (Debian, Red Hat, Alpine…)",
    "kernel": "Versión de kernel",
    "client": "Cliente",
    "environment": "Entorno",
    "tag": "Etiqueta",
    "status": "Estado del último escaneo",
    "reboot": "Requiere reinicio",
    "security": "Act. de seguridad pendientes",
    "update_age": "Antigüedad de la última actualización",
    "package_version": "Versión de un paquete (apache, openssl…)",
    "containers": "Docker / Podman",
}
KINDS = {"pie": "Quesito", "doughnut": "Dónut", "bar": "Barras"}
FILTERS = ("client", "environment", "tag", "os_family", "os_name")

# La familia se detecta por el gestor de paquetes del servidor (dpkg, rpm o apk)
FAMILY = {"deb": "Debian/Ubuntu", "rpm": "Red Hat/Rocky/Alma/SUSE", "apk": "Alpine",
          "": "(sin datos)", None: "(sin datos)"}
STATUS = {"ok": "Escaneo correcto", "error": "Escaneo con error", "never": "Nunca escaneado"}
NONE = "(sin datos)"  # servidores nunca escaneadas o cuyo escaneo siempre ha fallado
NONE_VALUE = "__none__"


def as_list(value):
    """Un filtro puede ser un valor (gráficos antiguos) o una lista (selección múltiple)."""
    if not value:
        return []
    return [str(v) for v in value if v] if isinstance(value, (list, tuple)) else [str(value)]


def _vms(filters):
    where, args = [], []
    for f in ("client", "environment", "os_family", "os_name"):
        vals = as_list(filters.get(f))
        if vals:
            where.append(f"COALESCE({f},'') IN ({','.join('?' * len(vals))})")
            args += ["" if v == NONE_VALUE else v for v in vals]
    tags = [int(t) for t in as_list(filters.get("tag")) if t.isdigit()]
    if tags:
        where.append(f"id IN (SELECT vm_id FROM vm_tags WHERE tag_id IN ({','.join('?' * len(tags))}))")
        args += tags
    sql = "SELECT * FROM vms" + (" WHERE " + " AND ".join(where) if where else "")
    return db.q(sql, args)


def _age_bucket(ts):
    if not ts:
        return "(desconocida)", None
    try:
        days = (datetime.now(db.TZ) - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=db.TZ)).days
    except ValueError:
        return "(desconocida)", None
    for limit, label in ((7, "< 7 días"), (30, "7-30 días"), (90, "30-90 días"), (365, "90-365 días")):
        if days < limit:
            return label, None
    return "> 1 año", None


def _link(params):
    return "/vms?" + urlencode(params, doseq=True)


def compute(chart, filters):
    """Devuelve [(etiqueta, nº servidores, enlace)] ordenado de mayor a menor."""
    vms = _vms(filters)
    dim = chart["dimension"]
    counts, links = Counter(), {}
    base = {k: v for k, v in filters.items() if v}

    def add(label, link=None):
        counts[label] += 1
        if link and label not in links:
            links[label] = link

    if dim == "tag":
        tags = {}
        for r in db.q("SELECT vt.vm_id, t.id, t.name FROM vm_tags vt JOIN tags t ON t.id=vt.tag_id"):
            tags.setdefault(r["vm_id"], []).append((r["id"], r["name"]))
        for v in vms:
            for tag_id, name in tags.get(v["id"], []) or [(None, "(sin etiqueta)")]:
                add(name, _link({**base, "tag": tag_id}) if tag_id else None)
    elif dim == "package_version":
        names = [n.strip() for n in (chart["package"] or "").split(",") if n.strip()]
        versions = {}
        if names and vms:
            rows = db.q(f"""SELECT vm_id, name, version FROM packages WHERE name IN ({','.join('?' * len(names))})
                            AND vm_id IN ({','.join('?' * len(vms))}) ORDER BY container IS NOT NULL, name""",
                        (*names, *[v["id"] for v in vms]))
            for r in rows:
                versions.setdefault(r["vm_id"], (r["name"], r["version"]))
        for v in vms:
            if v["last_ok_at"] is None and v["id"] not in versions:
                add(NONE)
            elif v["id"] in versions:
                name, ver = versions[v["id"]]
                label = f"{name} {ver}" if len(names) > 1 else ver
                add(label, "/search?" + urlencode({"pkg": name, "exact": 1, "op": "=", "ver": ver, **base}, doseq=True))
            else:
                add("(no instalado)")
    else:
        for v in vms:
            scanned = v["last_ok_at"] is not None
            if dim == "os":
                if v["os_name"]:
                    add(f"{v['os_name']} {v['os_version'] or ''}".strip(),
                        _link({**base, "os_name": v["os_name"], "os_version": v["os_version"] or NONE_VALUE}))
                else:
                    add(NONE)
            elif dim in ("os_name", "os_version", "kernel"):
                val = v[dim]
                add(val or NONE, _link({**base, dim: val}) if val else None)
            elif dim == "os_family":
                add(FAMILY.get(v["os_family"], v["os_family"]),
                    _link({**base, "os_family": v["os_family"] or NONE_VALUE}))
            elif dim in ("client", "environment"):
                add(v[dim] or f"(sin {'cliente' if dim == 'client' else 'entorno'})",
                    _link({**base, dim: v[dim] or NONE_VALUE}))
            elif dim == "status":
                add(STATUS.get(v["last_scan_status"], v["last_scan_status"]),
                    _link({**base, "status": v["last_scan_status"]}))
            elif dim == "reboot":
                if not scanned:
                    add(NONE)
                elif v["reboot_required"]:
                    add("Requiere reinicio", _link({**base, "reboot": 1}))
                else:
                    add("No requiere")
            elif dim == "security":
                n = v["pending_security"]
                add(NONE if not scanned else "(desconocido)" if n is None else "0" if n == 0
                    else "1-5" if n <= 5 else "6-20" if n <= 20 else "> 20")
            elif dim == "update_age":
                add(_age_bucket(v["last_pkg_update"])[0] if scanned else NONE)
            elif dim == "containers":
                if not scanned:
                    add(NONE)
                elif v["container_count"] is None:
                    add("Sin Docker ni Podman", _link({**base, "containers": "no"}))
                else:
                    add("Con Docker/Podman", _link({**base, "containers": "yes"}))
    return [(label, n, links.get(label)) for label, n in counts.most_common()], len(vms)


ORDERED = {
    "update_age": ["< 7 días", "7-30 días", "30-90 días", "90-365 días", "> 1 año", "(desconocida)", NONE],
    "security": ["0", "1-5", "6-20", "> 20", "(desconocido)", NONE],
}


def data(chart, filters):
    rows, total = compute(chart, filters)
    order = ORDERED.get(chart["dimension"])
    if order:
        rows.sort(key=lambda r: order.index(r[0]) if r[0] in order else 99)
    limit = 7 if chart["kind"] in ("pie", "doughnut") else 15
    if len(rows) > limit + 1:
        rest = rows[limit:]
        rows = rows[:limit] + [(f"Otros ({len(rest)})", sum(r[1] for r in rest), None)]
    return {"labels": [r[0] for r in rows], "values": [r[1] for r in rows],
            "links": [r[2] for r in rows], "total": total}
