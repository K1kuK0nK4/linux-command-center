"""End-of-life (EOL) detection with the public data from endoflife.date.

Nothing about the inventory leaves the machine: the app downloads, in a single request, the public
catalog of every product with its release cycles and the package names it is known by
(https://endoflife.date/api/v1/products/full) and keeps it in the database, so it keeps working
offline with the last download.

- Operating systems: matched by the os-release ID and VERSION_ID of each server.
- Applications: detected automatically, matching the installed package names against the catalog
  (plus a few built-in patterns for versioned names such as php8.1-cli). No list to maintain.
- Vendor: the scan records who built each package (rpm Vendor / dpkg Maintainer). Packages from the
  server's own distribution keep getting backported fixes after the upstream end of life, so only
  third-party packages (Docker, MySQL Community, NodeSource...) count for the EOL:App tag.
"""
import fnmatch
import json
import re
import urllib.request
from datetime import date

from . import db

API = "https://endoflife.date/api/v1/products/full"
SOON_DAYS = 90
MAX_BYTES = 30_000_000

# os-release ID -> endoflife.date product
OS_PRODUCTS = {"ubuntu": "ubuntu", "debian": "debian", "rhel": "rhel", "rocky": "rocky-linux",
               "almalinux": "almalinux", "centos": "centos", "ol": "oracle-linux", "alpine": "alpine-linux",
               "amzn": "amazon-linux", "sles": "sles", "fedora": "fedora"}
# Fallback by distribution name (containers only store the name)
OS_NAMES = {"ubuntu": "ubuntu", "debian gnu/linux": "debian", "red hat enterprise linux": "rhel",
            "rocky linux": "rocky-linux", "almalinux": "almalinux", "centos linux": "centos",
            "oracle linux server": "oracle-linux", "alpine linux": "alpine-linux", "amazon linux": "amazon-linux",
            "fedora linux": "fedora"}
# Catalog categories that are not installable applications
SKIP_CATEGORIES = {"os", "device", "service", "standard"}
# Built-in patterns for versioned package names the catalog does not list
PATTERNS = [
    ("php", ["php[0-9]*-cli", "php[0-9]*-common", "php-cli", "php-common"]),
    ("python", ["python3.*", "python3[0-9]*"]),
    ("postgresql", ["postgresql-[0-9]*", "postgresql[0-9]*-server"]),
    ("mysql", ["mysql-server-[0-9]*", "mysql-community-server"]),
    ("mariadb", ["mariadb-server-[0-9]*"]),
    ("tomcat", ["tomcat[0-9]*"]),
    ("apache-http-server", ["apache2"]),
    ("redis", ["redis-server"]),
    ("mongodb", ["mongodb-org-server"]),
]

# Who builds the distribution's own rpm packages, by os-release ID
RPM_VENDORS = {"rhel": r"Red Hat", "centos": r"CentOS", "rocky": r"Rocky", "almalinux": r"AlmaLinux",
               "ol": r"Oracle", "amzn": r"Amazon", "sles": r"SUSE", "opensuse-leap": r"SUSE|openSUSE",
               "fedora": r"Fedora"}
DEB_DISTRO = re.compile(r"@(lists\.)?(ubuntu\.com|canonical\.com|debian\.org)|@tracker\.debian\.org"
                        r"|alioth-lists\.debian\.net|lists\.alioth\.debian\.org", re.I)


def enabled():
    return db.get_setting("online_updates", "1") == "1"


# ---------- download (runs in a worker thread: no database access here) ----------

def _opener(proxy):
    handlers = [urllib.request.ProxyHandler({"https": proxy, "http": proxy})] if proxy else []
    return urllib.request.build_opener(*handlers)


def _release(r):
    """v1 release -> the stored format {cycle, eol, extendedSupport, latest}."""
    latest = r.get("latest")
    return {"cycle": r.get("name"), "eol": r.get("eolFrom") or bool(r.get("isEol")),
            "extendedSupport": r.get("eoesFrom"),
            "latest": latest.get("name") if isinstance(latest, dict) else latest}


def parse_catalog(catalog):
    """({product: cycles}, {package name: product}) from the v1 'products/full' answer."""
    data, index = {}, {}
    for p in sorted(catalog.get("result") or [], key=lambda p: str(p.get("name"))):
        name = p.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.\-]*", name):
            continue
        data[name] = [_release(r) for r in p.get("releases") or [] if isinstance(r, dict) and r.get("name")]
        if p.get("category") in SKIP_CATEGORIES:
            continue
        for ident in p.get("identifiers") or []:
            kind, value = ident.get("type"), str(ident.get("id") or "")
            if kind == "repology":
                pkg = value
            elif kind == "purl" and value.split(":", 1)[-1].split("/")[0] in ("deb", "rpm", "apk"):
                pkg = value.split("/")[-1].split("@")[0]
            else:
                continue
            if pkg:
                index.setdefault(pkg, name)
    return data, index


def download(proxy=""):
    """(data, index, errors): the whole catalog in one request."""
    req = urllib.request.Request(API, headers={"User-Agent": "linux-command-center", "Accept": "application/json"})
    try:
        with _opener(proxy).open(req, timeout=60) as r:
            body = r.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("response too large")
        catalog = json.loads(body)
        if not isinstance(catalog, dict) or not isinstance(catalog.get("result"), list):
            raise ValueError("unexpected format")
        data, index = parse_catalog(catalog)
        return data, index, {}
    except Exception as e:      # network error, proxy, bad JSON...
        return {}, {}, {"endoflife.date": f"{type(e).__name__}: {e}"}


def store(data, index):
    if not data:
        return
    with db.tx() as c:
        for product, cycles in data.items():
            c.execute("INSERT OR REPLACE INTO online_data(source, key, data, fetched_at) VALUES('eol',?,?,?)",
                      (product, json.dumps(cycles), db.now()))
        c.execute("INSERT OR REPLACE INTO online_data(source, key, data, fetched_at) VALUES('eol_index','packages',?,?)",
                  (json.dumps(index), db.now()))
    _CACHE.clear()
    _PRODUCT.clear()


def last_update():
    row = db.q1("SELECT MAX(fetched_at) t FROM online_data WHERE source='eol'")
    return row["t"] if row else None


# ---------- evaluation ----------

_CACHE = {}
_PRODUCT = {}


def cycles(product):
    if product not in _CACHE:
        row = db.q1("SELECT data FROM online_data WHERE source='eol' AND key=?", (product,))
        _CACHE[product] = json.loads(row["data"]) if row and row["data"] else None
    return _CACHE[product]


def _index():
    if "__index__" not in _PRODUCT:
        row = db.q1("SELECT data FROM online_data WHERE source='eol_index' AND key='packages'")
        _PRODUCT["__index__"] = json.loads(row["data"]) if row and row["data"] else {}
    return _PRODUCT["__index__"]


def product_for(package):
    """endoflife.date product of a package name, or None (memoized: the names repeat across servers)."""
    if package not in _PRODUCT:
        product = _index().get(package)
        if not product:
            product = next((p for p, pats in PATTERNS if any(fnmatch.fnmatchcase(package, x) for x in pats)), None)
        _PRODUCT[package] = product
    return _PRODUCT[package]


def version_candidates(version):
    """'1:3.0.13-0ubuntu3.4' -> ['3.0.13', '3.0', '3']; '1.1.1k' -> ['1.1.1', '1.1', '1']."""
    v = re.sub(r"^\d+:", "", version or "")
    v = re.split(r"[-+~_ ]", v)[0]
    parts = re.findall(r"\d+", v)
    return [".".join(parts[:n]) for n in range(len(parts), 0, -1)]


def _when(value):
    """endoflife.date uses a date, true (already EOL, date unknown) or false (no EOL announced)."""
    if value is True:
        return "eol", None
    if not value:
        return "ok", None
    try:
        d = date.fromisoformat(str(value))
    except ValueError:
        return "unknown", None
    days = (d - date.today()).days
    return ("eol" if days < 0 else "soon" if days <= SOON_DAYS else "ok"), d.isoformat()


def status(product, version):
    """{'product', 'cycle', 'state': ok|soon|eol|unknown, 'eol': 'YYYY-MM-DD' or None, ...}."""
    data = cycles(product)
    base = {"product": product, "version": version, "cycle": None, "state": "unknown", "eol": None,
            "extended": None, "latest": None}
    if not data or not version:
        return base
    by_cycle = {str(c["cycle"]): c for c in data}
    for cand in version_candidates(version):
        if cand in by_cycle:
            c = by_cycle[cand]
            state, eol_date = _when(c.get("eol"))
            ext = c.get("extendedSupport")
            return {**base, "cycle": cand, "state": state, "eol": eol_date,
                    "extended": ext if isinstance(ext, str) else None, "latest": c.get("latest")}
    return base


def os_product(vm):
    keys = vm.keys() if hasattr(vm, "keys") else ()
    os_id = vm["os_id"] if "os_id" in keys else None
    return OS_PRODUCTS.get(os_id or "") or OS_NAMES.get((vm["os_name"] or "").lower())


def os_status(vm):
    product = os_product(vm)
    return status(product, vm["os_version"]) if product else {"state": "unknown", "product": None}


def third_party(os_id, pkg):
    """True if the package does not come from the server's own distribution, False if it does,
    None if unknown (version probes, or scanned before the vendor was recorded)."""
    source, vendor = pkg["source"], pkg["vendor"]
    if source == "apk":
        return False
    if source not in ("rpm", "deb") or vendor is None:
        return None
    if source == "rpm":
        own = RPM_VENDORS.get(os_id or "")
        if own:
            return not re.search(own, vendor, re.I)
        return not re.search("|".join(v for k, v in RPM_VENDORS.items() if k != "fedora"), vendor, re.I)
    if "sury" in (pkg["version"] or "") or "sury" in vendor:     # the popular PHP PPA keeps Debian's maintainer
        return True
    return not DEB_DISTRO.search(vendor)


def app_status(vm_id, os_id=None):
    """Applications installed on the server (host packages) that are in the catalog, one row per cycle."""
    out, seen = [], set()
    for pkg in db.q("SELECT name, version, source, vendor FROM packages WHERE vm_id=? AND container IS NULL "
                    "AND source NOT IN ('kernel', 'snap') ORDER BY name", (vm_id,)):
        product = product_for(pkg["name"])
        if not product:
            continue
        st = status(product, pkg["version"])
        key = (product, st["cycle"] or pkg["version"])
        if key in seen:
            continue
        seen.add(key)
        out.append({**st, "package": pkg["name"], "vendor": pkg["vendor"], "third_party": third_party(os_id, pkg)})
    order = {"eol": 0, "soon": 1, "ok": 2, "unknown": 3}
    return sorted(out, key=lambda a: (order[a["state"]], a["product"]))


# ---------- automatic tags ----------

OS_TAG = "EOL:SO"      # the server's operating system is past its end of life
APP_TAG = "EOL:App"    # at least one third-party application is past its end of life
AUTO_TAGS = (OS_TAG, APP_TAG)
TAG_COLOR = "#e34948"


def _tag_id(c, name):
    row = c.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()
    if row:
        return row["id"]
    return c.execute("INSERT INTO tags(name, color) VALUES(?,?)", (name, TAG_COLOR)).lastrowid


def auto_tag_ids():
    return {r["id"] for r in db.q(f"SELECT id FROM tags WHERE name IN ({','.join('?' * len(AUTO_TAGS))})",
                                  AUTO_TAGS)}


def sync_tags(vm_ids=None):
    """Adds or removes the EOL:SO / EOL:App tags to match the current end-of-life state.
    Servers without data keep no tag (unknown is not end of life). Returns {tag: servers tagged}."""
    vms = db.q("SELECT * FROM vms") if vm_ids is None else \
        db.q(f"SELECT * FROM vms WHERE id IN ({','.join('?' * len(vm_ids))})", list(vm_ids)) if vm_ids else []
    wanted = {OS_TAG: set(), APP_TAG: set()}
    for v in vms:
        if os_status(v)["state"] == "eol":
            wanted[OS_TAG].add(v["id"])
        if any(a["state"] == "eol" and a["third_party"] for a in app_status(v["id"], v["os_id"])):
            wanted[APP_TAG].add(v["id"])
    ids = [v["id"] for v in vms]
    with db.tx() as c:
        for name, tagged in wanted.items():
            tag_id = _tag_id(c, name)
            c.executemany("DELETE FROM vm_tags WHERE vm_id=? AND tag_id=?",
                          [(i, tag_id) for i in ids if i not in tagged])
            c.executemany("INSERT OR IGNORE INTO vm_tags(vm_id, tag_id) VALUES(?,?)", [(i, tag_id) for i in tagged])
    db.bump()
    return {name: len(tagged) for name, tagged in wanted.items()}
