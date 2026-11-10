"""Customizable charts: they group the servers by the chosen dimension."""
from collections import Counter
from datetime import datetime
from functools import cmp_to_key
from urllib.parse import parse_qs, urlencode

from . import db, eol, versions

DIMENSIONS = {
    "os": "Operating system + version",
    "os_name": "Distribution",
    "os_version": "OS version",
    "os_family": "Family (Debian, Red Hat, Alpine…)",
    "kernel": "Kernel version",
    "client": "Organization",
    "environment": "Environment",
    "tag": "Tag",
    "status": "Last scan status",
    "reboot": "Reboot required",
    "security": "Pending security updates",
    "update_age": "Age of the last update",
    "package_version": "Package version (apache, openssl…)",
    "oldest_version": "Oldest version of a package (server ranking)",
    "tag_key": "Tag with key (e.g. Vendor:…)",
    "containers": "Docker / Podman",
    "support": "OS support (end of life)",
}
KINDS = {"pie": "Pie", "doughnut": "Donut", "bar": "Bars"}
FILTERS = ("client", "environment", "tag", "os_family", "os_name")

# The family is detected from the server's package manager (dpkg, rpm or apk)
FAMILY = {"deb": "Debian/Ubuntu", "rpm": "Red Hat/Rocky/Alma/SUSE", "apk": "Alpine",
          "": "(no data)", None: "(no data)"}
STATUS = {"ok": "Scan OK", "error": "Scan failed", "never": "Never scanned"}
NONE = "(no data)"  # servers never scanned, or whose scans have always failed
NONE_VALUE = "__none__"


def as_list(value):
    """A filter can be a single value (old charts) or a list (multiple selection)."""
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
    tags = sorted({int(t) for t in as_list(filters.get("tag")) if t.isdigit()})
    if tags:   # several tags: the server must have all of them (same rule as the inventory)
        where.append(f"id IN (SELECT vm_id FROM vm_tags WHERE tag_id IN ({','.join('?' * len(tags))}) "
                     "GROUP BY vm_id HAVING COUNT(DISTINCT tag_id)=?)")
        args += [*tags, len(tags)]
    sql = "SELECT * FROM vms" + (" WHERE " + " AND ".join(where) if where else "")
    return db.q(sql, args)


def _age_bucket(ts):
    """(label, code of the upd_age inventory filter)."""
    if not ts:
        return "(unknown)", "unknown"
    try:
        days = (datetime.now(db.TZ) - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=db.TZ)).days
    except ValueError:
        return "(unknown)", "unknown"
    for limit, label in ((7, "< 7 days"), (30, "7-30 days"), (90, "30-90 days"), (365, "90-365 days")):
        if days < limit:
            return label, str(limit)
    return "> 1 year", "old"


def _sec_bucket(n):
    if n is None:
        return "(unknown)", "unknown"
    if n == 0:
        return "0", "0"
    return ("1-5", "1-5") if n <= 5 else ("6-20", "6-20") if n <= 20 else ("> 20", "20+")


def _link(params):
    return "/vms?" + urlencode(params, doseq=True)


def compute(chart, filters):
    """Returns [(label, number of servers, link)] sorted from highest to lowest."""
    vms = _vms(filters)
    dim = chart["dimension"]
    counts, links = Counter(), {}
    base = {k: v for k, v in filters.items() if v}
    none_link = _link({**base, "never_ok": 1})   # never successfully scanned

    def add(label, link=None):
        counts[label] += 1
        if link and label not in links:
            links[label] = link

    if dim == "tag_key":
        # Key:value tags: grouped by the value of the given key (e.g. Vendor)
        key = (chart["package"] or "").strip().rstrip(":")
        values = {}
        for r in db.q("SELECT vt.vm_id, t.id, t.name FROM vm_tags vt JOIN tags t ON t.id=vt.tag_id "
                      "WHERE t.name LIKE ? ESCAPE '\\'", (key.replace("%", "\\%").replace("_", "\\_") + ":%",)):
            values.setdefault(r["vm_id"], []).append((r["id"], r["name"].split(":", 1)[1]))
        for v in vms:
            for tag_id, value in values.get(v["id"], []) or [(None, f"(no {key})")]:
                add(value, _link({**base, "tag": tag_id}) if tag_id else None)
    elif dim == "tag":
        tags = {}
        for r in db.q("SELECT vt.vm_id, t.id, t.name FROM vm_tags vt JOIN tags t ON t.id=vt.tag_id"):
            tags.setdefault(r["vm_id"], []).append((r["id"], r["name"]))
        for v in vms:
            for tag_id, name in tags.get(v["id"], []) or [(None, "(no tag)")]:
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
                add(NONE, none_link)
            elif v["id"] in versions:
                name, ver = versions[v["id"]]
                label = f"{name} {ver}" if len(names) > 1 else ver
                add(label, "/search?" + urlencode({"pkg": name, "exact": 1, "op": "=", "ver": ver, **base}, doseq=True))
            else:
                add("(not installed)")
    else:
        for v in vms:
            scanned = v["last_ok_at"] is not None
            if dim == "os":
                if v["os_name"]:
                    label = f"{v['os_name']} {v['os_version'] or ''}".strip()
                    add(label, _link({**base, "os": label}))
                else:
                    add(NONE, none_link)
            elif dim in ("os_name", "os_version", "kernel"):
                val = v[dim]
                add(val or NONE, _link({**base, dim: val}) if val else none_link)
            elif dim == "os_family":
                add(FAMILY.get(v["os_family"], v["os_family"]),
                    _link({**base, "os_family": v["os_family"] or NONE_VALUE}))
            elif dim in ("client", "environment"):
                add(v[dim] or '(no organization)' if dim == 'client' else '(no environment)',
                    _link({**base, dim: v[dim] or NONE_VALUE}))
            elif dim == "status":
                add(STATUS.get(v["last_scan_status"], v["last_scan_status"]),
                    _link({**base, "status": v["last_scan_status"]}))
            elif not scanned:
                add(NONE, none_link)
            elif dim == "reboot":
                if v["reboot_required"]:
                    add("Reboot required", _link({**base, "reboot": 1}))
                else:
                    add("Not required", _link({**base, "reboot": "no"}))
            elif dim == "security":
                label, code = _sec_bucket(v["pending_security"])
                add(label, _link({**base, "sec": code}))
            elif dim == "update_age":
                label, code = _age_bucket(v["last_pkg_update"])
                add(label, _link({**base, "upd_age": code}))
            elif dim == "containers":
                if v["container_count"] is None:
                    add("No Docker or Podman", _link({**base, "containers": "no"}))
                else:
                    add("With Docker/Podman", _link({**base, "containers": "yes"}))
            elif dim == "support":
                state = eol.os_status(v)["state"]
                add(SUPPORT[state], _link({**base, "eol": state}))
    return [(label, n, links.get(label)) for label, n in counts.most_common()], len(vms)


SUPPORT = {"ok": "Supported", "soon": "Support ends within 90 days", "eol": "End of life", "unknown": "(unknown)"}
ORDERED = {
    "update_age": ["< 7 days", "7-30 days", "30-90 days", "90-365 days", "> 1 year", "(unknown)", NONE],
    "security": ["0", "1-5", "6-20", "> 20", "(unknown)", NONE],
    "support": [SUPPORT[k] for k in ("ok", "soon", "eol", "unknown")] + [NONE],
}


def _merge_links(links):
    """Merges the inventory links of several categories (same filters, combined values).
    If they cannot be combined (one is missing or they filter by different things), there is no link."""
    if not links or any(not l or not l.startswith("/vms?") for l in links):
        return None
    parsed = [parse_qs(l[len("/vms?"):]) for l in links]
    if any(p.keys() != parsed[0].keys() for p in parsed):
        return None
    merged = {k: sorted({v for p in parsed for v in p[k]}) for k in parsed[0]}
    return _link(merged)


RANKING_SIZE = 15


def oldest(chart, filters):
    """The servers with the oldest version of the package (on the host), from oldest to newest.
    Uses the real rpm/dpkg comparison; between different families there is no possible order, so they
    are grouped by family (it is best to filter by distribution)."""
    vms = {v["id"]: v for v in _vms(filters)}
    names = [n.strip() for n in (chart["package"] or "").split(",") if n.strip()]
    if not names or not vms:
        return [], len(vms)
    found = {}
    for r in db.q(f"""SELECT vm_id, name, version FROM packages WHERE container IS NULL
                      AND name IN ({','.join('?' * len(names))}) AND vm_id IN ({','.join('?' * len(vms))})
                      ORDER BY name""", (*names, *vms)):
        found.setdefault(r["vm_id"], (r["name"], r["version"]))

    def cmp(a, b):
        fa, fb = vms[a[0]]["os_family"] or "", vms[b[0]]["os_family"] or ""
        if fa != fb:
            return -1 if fa < fb else 1
        try:
            return versions.compare(a[1][1], b[1][1], fa)
        except Exception:
            return 0

    ranked = sorted(found.items(), key=cmp_to_key(cmp))[:max_results(chart) or RANKING_SIZE]
    rows = [{"server": vms[vm_id]["name"], "package": name, "version": ver,
             "os": f"{vms[vm_id]['os_name'] or ''} {vms[vm_id]['os_version'] or ''}".strip(),
             "link": f"/vms/{vm_id}"} for vm_id, (name, ver) in ranked]
    return rows, len(vms)


def max_results(chart):
    """Optional per-chart limit (None = show everything)."""
    keys = chart.keys() if hasattr(chart, "keys") else ()
    value = chart["max_results"] if "max_results" in keys else None
    return int(value) if value else None


def data(chart, filters):
    if chart["dimension"] == "oldest_version":
        rows, total = oldest(chart, filters)
        return {"labels": [r["server"] for r in rows], "values": [1] * len(rows),
                "links": [r["link"] for r in rows], "ranking": rows, "total": total}
    rows, total = compute(chart, filters)
    order = ORDERED.get(chart["dimension"])
    if order:
        rows.sort(key=lambda r: order.index(r[0]) if r[0] in order else 99)
    # Every category is shown; "Max results" (optional, per chart) keeps only the biggest ones
    limit = max_results(chart)
    if limit:
        rows = rows[:limit]
    return {"labels": [r[0] for r in rows], "values": [r[1] for r in rows],
            "links": [r[2] for r in rows], "total": total}
