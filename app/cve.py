"""CVE lookup: which servers are affected by a CVE, according to each distribution's vendor.

Only the CVE ID leaves this computer: the app reads the public JSON of each source and compares the
fixed version it gives with the versions in the inventory (rpm/dpkg rules, backports included).

  Red Hat   access.redhat.com/hydra/rest/securitydata   RHEL (also Rocky, Alma, CentOS, Oracle Linux)
  Ubuntu    ubuntu.com/security/cves                    (OSV copy as fallback)
  Debian    api.osv.dev  DEBIAN-CVE-...
  Alpine    api.osv.dev  ALPINE-CVE-...
  CISA KEV  known exploited vulnerabilities catalog (downloaded once a day with the end-of-life data)

The result is version-based: conditions such as "only if HTTP/2 is enabled" are not evaluated. The
vendor's notes and mitigation text are shown so they can be checked by hand.
Vendors publish fixes per SOURCE package (apache2), while servers have binary packages
(apache2-bin...): the scan records the source package of each one.
"""
import fnmatch
import json
import re
from functools import cmp_to_key
import urllib.error
import urllib.request
from datetime import datetime

from . import db, eol, versions

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
SOURCES = {
    "redhat": "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json",
    "ubuntu": "https://ubuntu.com/security/cves/{}.json",
    "osv_ubuntu": "https://api.osv.dev/v1/vulns/UBUNTU-{}",
    "debian": "https://api.osv.dev/v1/vulns/DEBIAN-{}",
    "alpine": "https://api.osv.dev/v1/vulns/ALPINE-{}",
    # The software's own vendor: used for third-party packages and software installed by hand
    "cveorg": "https://cveawg.mitre.org/api/cve/{}",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
}
SOURCE_NAMES = {"redhat": "Red Hat", "ubuntu": "Ubuntu", "osv_ubuntu": "Ubuntu (OSV)", "debian": "Debian",
                "alpine": "Alpine", "cveorg": "CVE.org", "nvd": "NVD"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 5_000_000
KEV_MAX_BYTES = 40_000_000
CACHE_HOURS = 6

# os-release ID -> family of the security data
FAMILY = {"rhel": "rhel", "rocky": "rhel", "almalinux": "rhel", "centos": "rhel", "ol": "rhel",
          "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine"}
NAME_FAMILY = (("red hat", "rhel"), ("rocky", "rhel"), ("almalinux", "rhel"), ("centos", "rhel"),
               ("oracle linux", "rhel"), ("ubuntu", "ubuntu"), ("debian", "debian"), ("alpine", "alpine"))
UBUNTU_CODENAMES = {"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04",
                    "oracular": "24.10", "plucky": "25.04", "questing": "25.10", "resolute": "26.04"}
UBUNTU_FIXED = {"released"}
UBUNTU_NOT_AFFECTED = {"not-affected", "DNE"}
UBUNTU_WONTFIX = {"ignored"}
UBUNTU_UNKNOWN = {"needs-triage"}                 # not analysed by the vendor yet
RH_NOT_AFFECTED = {"Not affected"}
RH_WONTFIX = {"Will not fix", "Out of support scope"}
RH_UNKNOWN = {"Under investigation"}
VERSION_LIKE = re.compile(r"\d")

# Result states, from worst to best
STATES = ["vulnerable", "vulnerable_nofix", "wontfix", "upstream_vulnerable", "third_party", "no_data",
          "upstream_patched", "patched", "not_affected"]
BAD_STATES = ("vulnerable", "vulnerable_nofix", "wontfix", "upstream_vulnerable")
STATE_LABELS = {"vulnerable": "Vulnerable", "vulnerable_nofix": "Vulnerable, no fix yet",
                "wontfix": "Vulnerable, vendor will not fix",
                "upstream_vulnerable": "Vulnerable (software vendor's versions)",
                "upstream_patched": "Not vulnerable (software vendor's versions)",
                "third_party": "Third-party package: check with its vendor", "no_data": "No data",
                "patched": "Patched", "not_affected": "Not affected"}


def normalize(text):
    """'cve-2024-6387 ' -> 'CVE-2024-6387', or None if it is not a CVE ID."""
    cve = (text or "").strip().upper()
    return cve if CVE_RE.match(cve) else None


# ---------- download (worker thread: no database access) ----------

def _opener(proxy):
    handlers = [urllib.request.ProxyHandler({"https": proxy, "http": proxy})] if proxy else []
    return urllib.request.build_opener(*handlers)


def _get_json(opener, url, max_bytes=MAX_BYTES, timeout=20):
    """(data, error). A 404 is not an error: the source simply has no record for this CVE."""
    req = urllib.request.Request(url, headers={"User-Agent": "linux-command-center", "Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(max_bytes + 1)
        if len(body) > max_bytes:
            return None, "response too large"
        data = json.loads(body)
        if isinstance(data, str):            # Red Hat sometimes sends the JSON encoded twice (a JSON string)
            data = json.loads(data)
        if not isinstance(data, dict):
            return None, "unexpected format"  # never mistaken for "no record": that would hide servers
        return data, None
    except urllib.error.HTTPError as e:
        return (None, None) if e.code == 404 else (None, f"HTTP {e.code}")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def fetch(cve, proxy=""):
    """Reads every source for one CVE. {source: {"data": json or None, "error": str or None}}."""
    opener = _opener(proxy)
    out = {}
    for name, url in SOURCES.items():
        if name == "osv_ubuntu" and out.get("ubuntu", {}).get("data"):
            continue                                   # only needed when ubuntu.com fails
        data, error = _get_json(opener, url.format(cve))
        out[name] = {"data": _slim(name, data) if isinstance(data, dict) else None, "error": error}
    return {"sources": out}


def _slim(source, data):
    """Keeps only the fields the app uses, so the cache stays small (a kernel CVE can bring 250 KB)."""
    if source == "redhat":
        return {k: data.get(k) for k in ("threat_severity", "cvss3", "details", "statement", "mitigation",
                                          "affected_release", "package_state")}
    if source == "ubuntu":
        return {**{k: data.get(k) for k in ("description", "priority", "cvss3", "mitigation", "notes")},
                "packages": [{"name": p.get("name"),
                              "statuses": [{k: s.get(k) for k in ("release_codename", "status", "description", "pocket")}
                                           for s in p.get("statuses") or [] if isinstance(s, dict)
                                           and (s.get("release_codename") in UBUNTU_CODENAMES
                                                or s.get("release_codename") == "upstream")
                                           and s.get("status") != "DNE"]}   # "does not exist" in that release
                             for p in data.get("packages") or [] if isinstance(p, dict)]}
    if source == "cveorg":
        cna = (data.get("containers") or {}).get("cna") or {}
        return {"title": cna.get("title"), "descriptions": cna.get("descriptions"),
                "affected": cna.get("affected"), "workarounds": cna.get("workarounds")}
    if source == "nvd":
        cve = ((data.get("vulnerabilities") or [{}])[0] or {}).get("cve") or {}
        metrics = cve.get("metrics") or {}
        score = next((m[0].get("cvssData", {}).get("baseScore") for k in ("cvssMetricV31", "cvssMetricV40",
                      "cvssMetricV30") for m in [metrics.get(k)] if m), None)
        return {"status": cve.get("vulnStatus"), "score": score, "configurations": cve.get("configurations")}
    return {"details": data.get("details"),           # OSV
            "affected": [{"package": a.get("package"), "ranges": a.get("ranges")}
                         for a in data.get("affected") or [] if isinstance(a, dict)]}


def download_kev(proxy=""):
    """(catalog {cve: info}, error). Only the fields shown in the app are kept."""
    data, error = _get_json(_opener(proxy), KEV_URL, KEV_MAX_BYTES, timeout=60)
    if error or not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        return None, error or "unexpected format"
    catalog = {}
    for v in data["vulnerabilities"]:
        if isinstance(v, dict) and normalize(v.get("cveID")):
            catalog[v["cveID"].upper()] = {k: str(v.get(k) or "")[:500] for k in
                                           ("vulnerabilityName", "dateAdded", "dueDate", "requiredAction",
                                            "knownRansomwareCampaignUse")}
    return catalog, None


# ---------- cache in the database ----------

def cached(cve):
    row = db.q1("SELECT data, fetched_at FROM online_data WHERE source='cve' AND key=?", (cve,))
    if not row:
        return None
    try:
        age = (datetime.now(db.TZ) - datetime.strptime(row["fetched_at"], "%Y-%m-%d %H:%M:%S")
               .replace(tzinfo=db.TZ)).total_seconds()
    except ValueError:
        return None
    if age > CACHE_HOURS * 3600:
        return None
    data = json.loads(row["data"])
    if _failed(data.get("sources", {})):
        return None                    # a source failed last time: ask again instead of keeping the gap
    data["fetched_at"] = row["fetched_at"]
    return data


CACHE_MAX = 200          # lookups kept at most (the oldest go first)


def _failed(sources):
    """Sources that did not answer (Ubuntu does not count when its OSV copy answered instead)."""
    osv_ok = bool((sources.get("osv_ubuntu") or {}).get("data"))     # a 404 there does not replace ubuntu.com
    return [k for k, s in sources.items() if (s or {}).get("error") and not (k == "ubuntu" and osv_ok)]


def store(cve, data):
    ts = db.now()
    db.ex("INSERT OR REPLACE INTO online_data(source, key, data, fetched_at) VALUES('cve',?,?,?)",
          (cve, json.dumps({"sources": data["sources"]}), ts))
    prune()
    data["fetched_at"] = ts
    return data


def prune():
    """The cache never grows without limit: lookups older than a day, or beyond the newest CACHE_MAX, are
    deleted (looking them up again just asks the sources again)."""
    db.ex("DELETE FROM online_data WHERE source='cve' AND fetched_at < datetime('now','localtime','-1 day')")
    db.ex("""DELETE FROM online_data WHERE source='cve' AND key NOT IN
             (SELECT key FROM online_data WHERE source='cve' ORDER BY fetched_at DESC LIMIT ?)""", (CACHE_MAX,))


_KEV = {}


def store_kev(catalog):
    db.ex("INSERT OR REPLACE INTO online_data(source, key, data, fetched_at) VALUES('kev','catalog',?,?)",
          (json.dumps(catalog), db.now()))
    _KEV.clear()


def kev_info(cve):
    """CISA KEV entry for the CVE (actively exploited), or None."""
    if "catalog" not in _KEV:
        row = db.q1("SELECT data, fetched_at FROM online_data WHERE source='kev' AND key='catalog'")
        _KEV["catalog"] = json.loads(row["data"]) if row else None
        _KEV["fetched_at"] = row["fetched_at"] if row else None
    return (_KEV["catalog"] or {}).get(cve)


def kev_loaded():
    kev_info("CVE-0000-0000")
    return _KEV.get("catalog") is not None, _KEV.get("fetched_at")


# ---------- vendor data -> rules ----------
# rule = {"family", "release", "package", "state": fixed|affected|not_affected|wontfix, "fixed", "advisory", "via"}

def _rh_product(name):
    """'Red Hat Enterprise Linux 9' -> ('9', None); '... 9.8 Extended Update Support' -> ('9', '8').
    Variants with their own packages ("... 9 for SAP Solutions", "... for Real Time") are left out: only plain
    RHEL and its update streams of one minor (EUS, AUS, TUS, Update Services for SAP) count."""
    name = (name or "").strip()
    m = re.match(r"^Red Hat Enterprise Linux (\d+)$", name)
    if m:
        return m.group(1), None
    m = re.match(r"^Red Hat Enterprise Linux (\d+)\.(\d+) (.*(Support|Service|Services).*)$", name)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^Red Hat Enterprise Linux (\d+) Extended Lifecycle Support\b", name)
    if m:
        return m.group(1), "els"          # RHEL 6/7 after their end of life: used when there is nothing else
    return None, None


def parse_redhat(data):
    rules = []
    for r in data.get("affected_release") or []:
        if not isinstance(r, dict):
            continue
        major, minor = _rh_product(r.get("product_name"))
        if not major:
            continue                       # other products (OpenShift, Satellite...)
        pkg = str(r.get("package") or "")
        m = re.match(r"^(.+?)-(\d+):(.+)$", pkg)
        if not m:
            # RHEL 8 AppStream modules: "nginx:1.24-8100020240322095305.b6b5a0b3" is a module build, not a
            # package version. It cannot be compared, but the server must not disappear from the result.
            mod = re.match(r"^([A-Za-z0-9_.+-]+):", pkg)
            if mod:
                rules.append({"family": "rhel", "release": major, "minor": minor, "package": mod.group(1),
                              "state": "unknown", "fixed": None, "via": "Red Hat",
                              "advisory": f"{r.get('advisory') or ''} (module {pkg.split('-')[0]})".strip()})
            continue
        name, epoch, vr = m.groups()
        rules.append({"family": "rhel", "release": major, "minor": minor, "package": name, "state": "fixed",
                      "fixed": vr if epoch == "0" else f"{epoch}:{vr}", "advisory": r.get("advisory") or "",
                      "via": "Red Hat"})
    for s in data.get("package_state") or []:
        if not isinstance(s, dict):
            continue
        major, minor = _rh_product(s.get("product_name"))
        name = str(s.get("package_name") or "").split("/")[-1]
        if not major or not name:
            continue
        fix_state = s.get("fix_state") or ""
        state = ("not_affected" if fix_state in RH_NOT_AFFECTED else "wontfix" if fix_state in RH_WONTFIX
                 else "unknown" if fix_state in RH_UNKNOWN else "affected")
        rules.append({"family": "rhel", "release": major, "minor": minor, "package": name, "state": state,
                      "fixed": None, "advisory": fix_state, "via": "Red Hat"})
    return rules


def parse_ubuntu(data):
    rules = []
    for p in data.get("packages") or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        for s in p.get("statuses") or []:
            status, desc = s.get("status") or "", str(s.get("description") or "")
            if s.get("release_codename") == "upstream":
                # Fixed version(s) in the original project, e.g. "1.30.7, 1.31.3" (one per branch). Used only to
                # estimate third-party packages, which follow the project's numbering without backports.
                fixes = [f.strip() for f in desc.split(",") if f.strip()]
                if status in UBUNTU_FIXED and fixes:
                    rules.append({"family": "upstream", "release": "", "package": p["name"], "state": "fixed",
                                  "fixed": None, "fixes": fixes, "advisory": "", "via": "upstream"})
                elif status in ("needed", "pending", "deferred"):
                    rules.append({"family": "upstream", "release": "", "package": p["name"], "state": "affected",
                                  "fixed": None, "fixes": [], "advisory": "", "via": "upstream"})
                continue
            release = UBUNTU_CODENAMES.get(s.get("release_codename"))
            if not release:
                continue
            if status in UBUNTU_FIXED:
                pocket = s.get("pocket") or ""
                if not VERSION_LIKE.search(desc):         # "released" without a version: cannot compare
                    rules.append({"family": "ubuntu", "release": release, "package": p["name"], "state": "unknown",
                                  "fixed": None, "advisory": status, "via": "Ubuntu"})
                    continue
                rules.append({"family": "ubuntu", "release": release, "package": p["name"], "state": "fixed",
                              "fixed": desc.strip(), "via": "Ubuntu",
                              "advisory": "Ubuntu Pro (ESM)" if pocket.startswith("esm") else ""})
            else:
                state = ("not_affected" if status in UBUNTU_NOT_AFFECTED else "wontfix" if status in UBUNTU_WONTFIX
                         else "unknown" if status in UBUNTU_UNKNOWN else "affected")
                rules.append({"family": "ubuntu", "release": release, "package": p["name"], "state": state,
                              "fixed": None, "advisory": status, "via": "Ubuntu"})
    return rules


def parse_osv(data, via):
    """OSV records list only the affected releases: Debian:12, Alpine:v3.19, Ubuntu:24.04:LTS."""
    rules = []
    for a in data.get("affected") or []:
        pkg = (a or {}).get("package") or {}
        eco, name = str(pkg.get("ecosystem") or ""), pkg.get("name")
        m = re.match(r"^(Debian|Alpine|Ubuntu):v?(\d+(?:\.\d+)?)", eco)
        if not m or not name:
            continue
        family = m.group(1).lower()
        fixed = None
        introduced = None
        for rng in a.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed = ev["fixed"]
                if ev.get("introduced") and ev["introduced"] != "0":
                    introduced = ev["introduced"]       # versions before this one never had the flaw
        rules.append({"family": family, "release": m.group(2), "package": name,
                      "state": "fixed" if fixed else "affected", "fixed": fixed, "introduced": introduced,
                      "advisory": "", "via": via})
    return rules


def rules_of(fetched):
    src = fetched["sources"]
    data = lambda k: (src.get(k) or {}).get("data")
    rules = []
    if data("redhat"):
        rules += parse_redhat(data("redhat"))
    if data("ubuntu"):
        rules += parse_ubuntu(data("ubuntu"))
    elif data("osv_ubuntu"):
        rules += parse_osv(data("osv_ubuntu"), "Ubuntu (OSV)")
    if data("debian"):
        rules += parse_osv(data("debian"), "Debian")
    if data("alpine"):
        rules += parse_osv(data("alpine"), "Alpine")
    return rules


def info_of(fetched):
    """Description, severity and the vendors' notes / mitigation (free text, to be checked by hand)."""
    src = fetched["sources"]
    rh, ub = (src.get("redhat") or {}).get("data") or {}, (src.get("ubuntu") or {}).get("data") or {}
    osv = next(((src.get(k) or {}).get("data") for k in ("debian", "osv_ubuntu", "alpine")
                if (src.get(k) or {}).get("data")), None) or {}
    details = rh.get("details")
    description = (details[0] if isinstance(details, list) and details else details) or ub.get("description") \
        or osv.get("details") or ""
    notes = []
    if rh.get("statement"):
        notes.append(("Red Hat", "Statement", str(rh["statement"])))
    if isinstance(rh.get("mitigation"), dict) and rh["mitigation"].get("value"):
        notes.append(("Red Hat", "Mitigation", str(rh["mitigation"]["value"])))
    if ub.get("mitigation"):
        notes.append(("Ubuntu", "Mitigation", str(ub["mitigation"])))
    for n in ub.get("notes") or []:
        if isinstance(n, dict) and n.get("note"):
            notes.append(("Ubuntu", "Note", str(n["note"])))
    cna = (src.get("cveorg") or {}).get("data") or {}
    nvd = (src.get("nvd") or {}).get("data") or {}
    if not description:            # a third-party CVE the distributions do not track: the vendor's own text
        description = next((d.get("value") for d in cna.get("descriptions") or []
                            if isinstance(d, dict) and str(d.get("lang", "")).startswith("en")), "")
    for w in cna.get("workarounds") or []:
        if isinstance(w, dict) and w.get("value"):
            notes.append(("Vendor", "Workaround", str(w["value"])))
    cvss = (rh.get("cvss3") or {}).get("cvss3_base_score") if isinstance(rh.get("cvss3"), dict) else None
    return {"description": str(description).strip(), "notes": notes,
            "severity": rh.get("threat_severity") or (ub.get("priority") or "").capitalize() or None,
            "cvss": cvss or ub.get("cvss3") or nvd.get("score")}


def _range_text(r):
    if r["exact"]:
        return r["start"] or "?"
    low = f"{'≥' if r['start_incl'] else '>'} {r['start']}" if r["start"] else ""
    high = "no fix" if r["open"] else (f"{'≤' if r['end_incl'] else '<'} {r['end']}" if r["end"] else "")
    return " ".join(x for x in (low, high) if x) or "all"


def vendor_summary(fetched):
    """The software vendor's view, for the page: [{via, vendor, product, ranges: [text]}]."""
    return [{"via": e["via"], "vendor": e["vendor"], "product": e["product"],
             "ranges": [_range_text(r) for r in e["ranges"] if r["status"] == "affected"]}
            for e in vendor_data(fetched) if e["ranges"]]


# ---------- comparison with the inventory ----------

def _family(os_id, os_name):
    fam = FAMILY.get((os_id or "").lower())
    if fam:
        return fam
    name = (os_name or "").lower()
    return next((f for key, f in NAME_FAMILY if key in name), None)


def _release(family, version):
    v = str(version or "")
    if family == "rhel":
        parts = v.split(".")
        return parts[0], (parts[1] if len(parts) > 1 else None)
    if family == "debian":
        return v.split(".")[0], None
    if family == "alpine":
        return ".".join(v.split(".")[:2]), None
    return v, None


RULE_ORDER = {"fixed": 0, "affected": 1, "wontfix": 2, "not_affected": 3, "unknown": 4}
# Kernel binaries: what counts is the kernel that is RUNNING, not older ones left installed
KERNEL_BINARY = re.compile(r"^(linux-(image|modules|modules-extra|headers)(-unsigned)?-\d|kernel(-core|-modules"
                           r"(-core|-extra)?|-rt(-core|-modules)?|-uek(-core|-modules)?)?$)")


def _index(rules):
    idx = {}
    for r in rules:
        idx.setdefault((r["family"], r["release"], r["package"]), []).append(r)
    return idx


def _rule_for(idx, family, release, minor, package):
    cands = idx.get((family, release, package), [])
    if family == "rhel":
        # Extended Update Support stream of the same minor first, then the main stream
        exact = [r for r in cands if r.get("minor") and r["minor"] == minor]
        main = [r for r in cands if not r.get("minor")]
        els = [r for r in cands if r.get("minor") == "els"]      # Extended Lifecycle Support (RHEL 6/7)
        # Main stream and ELS together: a fix in ELS wins over "out of support scope" in the main stream
        cands = exact or (main + els)
    if not cands:
        return None
    rule = min(cands, key=lambda r: RULE_ORDER[r["state"]])
    fixes = sorted({r["fixed"] for r in cands if r["state"] == "fixed" and r["fixed"]})
    if len(fixes) > 1:              # several fixed versions (e.g. one per branch): chosen per installed version
        rule = {**rule, "alternatives": fixes}
    return rule


def _fixed_for(rule, version, family):
    """The fixed version that applies to this installed version: the one of its own branch when there are
    several, otherwise the lowest."""
    alts = rule.get("alternatives")
    if not alts:
        return rule["fixed"]
    lowest = lambda vs: min(vs, key=cmp_to_key(lambda a, b: versions.compare(a, b, family)))
    branch = _upstream_version(version).split(".")[:2]
    same = [f for f in alts if _upstream_version(f).split(".")[:2] == branch]
    return lowest(same or alts)


APK_PRERELEASE = re.compile(r"_(alpha|beta|pre|rc)")


def _state(rule, version, source):
    if not rule or rule["state"] == "unknown":
        return "no_data"
    family = "rpm" if source == "rpm" else "deb"
    if source == "apk":
        # Alpine: 1.2.3_rc1 comes BEFORE 1.2.3; with dpkg rules "~rc1" sorts that way
        version = APK_PRERELEASE.sub(r"~\1", version or "")
        rule = {**rule, **{k: APK_PRERELEASE.sub(r"~\1", rule[k]) for k in ("fixed", "introduced") if rule.get(k)}}
    try:
        if rule.get("introduced") and versions.compare(version, rule["introduced"], family) < 0:
            return "not_affected"                    # older than the version that introduced the flaw
        if rule["state"] != "fixed":
            return {"affected": "vulnerable_nofix", "wontfix": "wontfix",
                    "not_affected": "not_affected"}[rule["state"]]
        return "vulnerable" if versions.compare(version, _fixed_for(rule, version, family), family) < 0 else "patched"
    except Exception:
        return "no_data"


# Package names that differ between the third-party package and the project name used by Ubuntu
UPSTREAM_ALIASES = {"httpd": "apache2", "docker-ce": "docker.io", "mysql-community-server": "mysql-8.0"}
CONCRETE = re.compile(r"^\d+(\.\d+)*[a-z]?\d*$")      # 1.31.3, 9.8p1... not "6.8.y" nor "7.4~rc2"


def _upstream_version(version):
    """'2:1.30.6-1.el9.ngx' -> '1.30.6'; '1.31.2-1~trixie' -> '1.31.2'."""
    return re.sub(r"^\d+:", "", version or "").split("-")[0].split("~")[0]


def _upstream_estimate(idx, package, binaries, version):
    """Third-party package vs the project's fixed version (one per branch: the branch of the installed
    version is used). ('upstream_vulnerable' | 'upstream_patched' | 'third_party', fixed version)."""
    names = [package, *binaries]
    names += [UPSTREAM_ALIASES[n] for n in names if n in UPSTREAM_ALIASES]
    rule = next((r for n in names for r in idx.get(("upstream", "", n), [])), None)
    if not rule:
        return "third_party", None
    if rule["state"] == "affected":
        return "upstream_vulnerable", None                 # the project has no fix yet
    installed = _upstream_version(version)
    fixes = [f for f in rule["fixes"] if CONCRETE.match(f)]
    branch = [f for f in fixes if f.split(".")[:2] == installed.split(".")[:2]]
    lowest = lambda vs: min(vs, key=cmp_to_key(lambda a, b: versions.compare(a, b, "deb")))
    try:
        if branch:
            fix = lowest(branch)
        elif fixes and all(versions.compare(installed, f, "deb") < 0 for f in fixes):
            fix = lowest(fixes)                            # older than every fixed branch
        else:
            return "third_party", None                     # another branch: the fixed version is not known
        return ("upstream_vulnerable" if versions.compare(installed, fix, "deb") < 0 else "upstream_patched"), fix
    except Exception:
        return "third_party", None


def _runs(binary, version, running):
    """Is this installed kernel package the one running (uname -r)?"""
    if not running:
        return False
    if binary.startswith("linux-"):                       # Ubuntu/Debian: linux-image-5.15.0-203-generic
        return binary.endswith("-" + running)
    v = re.sub(r"^\d+:", "", version)                     # RHEL: 4.18.0-553.el8_10 vs 4.18.0-553.el8_10.x86_64
    return running == v or running.startswith(v + ".")


def evaluate(rules, vendor=None):
    """[{server, where, os, package, binaries, installed, fixed, advisory, via, state, note}] one row per
    server/container and package, worst first. rules: distribution data; vendor: the software vendor's ranges
    (for third-party packages and software installed by hand)."""
    vendor = vendor or []
    out = _evaluate_distro(rules, vendor) if rules else []
    if vendor:
        done = {(g["vm_id"], g["container"], eol.product_for(g["package"])) for g in out}
        out += _vendor_rows(vendor, done, {(r["family"], r["release"]) for r in rules})
    out.sort(key=lambda g: (STATES.index(g["state"]), g["server"] or "", g["container"] or ""))
    return out


def _canonical_src(src):
    """Signed kernel images come from 'linux-signed*' sources, but trackers publish the kernel as 'linux':
    Debian linux-signed-amd64 -> linux, Ubuntu linux-signed-hwe-6.8 -> linux-hwe-6.8."""
    return re.sub(r"^linux-signed(-(amd64|arm64|i386|ppc64el|s390x|armhf))?(?=-|$)", "linux", src or "")


# Source packages of a kernel: inside a container they never apply (it runs the host's kernel)
KERNEL_SOURCE = re.compile(r"^(linux|kernel)(-(hwe|lts|aws|azure|gcp|oem|lowlatency|rt|uek|oracle|ibm|kvm|"
                           r"raspi|realtime|nvidia|signed)[\w.+-]*)?$")


def _evaluate_distro(rules, vendor):
    names = sorted({r["package"] for r in rules})
    if not names:
        return []
    wanted = set(names)
    idx = _index(rules)
    covered = {(r["family"], r["release"]) for r in rules}     # OS versions the vendors say something about
    ph = ",".join("?" * len(names))
    signed = " OR p.src_name LIKE 'linux-signed%'" if any(n.startswith("linux") for n in names) else ""
    rows = db.q(f"""SELECT p.vm_id, p.name, p.version, p.source, p.container, p.src_name, p.vendor,
                          v.name vm_name, v.host, v.client, v.environment, v.os_id, v.os_name, v.os_version, v.kernel,
                          c.os_id c_os_id, c.os_name c_os_name, c.os_version c_os_version, c.image
                   FROM packages p JOIN vms v ON v.id=p.vm_id
                   LEFT JOIN containers c ON c.vm_id=p.vm_id AND c.name=p.container
                   WHERE p.source IN ('rpm','deb','apk')
                     AND (p.src_name IN ({ph}) OR (p.src_name IS NULL AND p.name IN ({ph})){signed})""",
                (*names, *names))
    groups = {}
    for r in rows:
        in_ct = r["container"] is not None
        is_kernel = bool(KERNEL_BINARY.match(r["name"]))
        package = _canonical_src(r["src_name"] or r["name"])
        if package not in wanted:
            continue
        if in_ct and (is_kernel or KERNEL_SOURCE.match(package)):
            continue                    # a container has no kernel of its own: it runs the host's
        os_id, os_name, os_ver = ((r["c_os_id"], r["c_os_name"], r["c_os_version"]) if in_ct
                                  else (r["os_id"], r["os_name"], r["os_version"]))
        family = _family(os_id, os_name)
        release, minor = _release(family, os_ver) if family else (None, None)
        rule = _rule_for(idx, family, release, minor, package) if family else None
        if not rule and (family, release) in covered and not (is_kernel and not in_ct
                                                               and _runs(r["name"], r["version"], r["kernel"])):
            continue        # the vendor covers this OS version but names other packages: this one is not involved
        g = groups.setdefault((r["vm_id"], r["container"], package), {
            "vm_id": r["vm_id"], "server": r["vm_name"], "host": r["host"], "client": r["client"],
            "environment": r["environment"], "container": r["container"], "image": r["image"],
            "os": f"{os_name or ''} {os_ver or ''}".strip(), "package": package, "rule": rule,
            "kernel": r["kernel"], "items": []})
        # A package built by someone else (nginx.org, Docker...) is not covered by the distribution's data
        third = eol.third_party(os_id, r) is True
        g["items"].append((r["name"], r["version"], r["source"], is_kernel, third, r["vendor"]))
    out = []
    for g in groups.values():
        items, note = g.pop("items"), ""
        kernels = [i for i in items if i[3]]
        rule = g.pop("rule")
        if kernels:
            running = [i for i in kernels if _runs(i[0], i[1], g["kernel"])]
            if running:
                items, note = running, "running kernel"
                if not rule:
                    note = "running kernel: the vendor publishes no data for it (e.g. Oracle UEK)"
            elif g["kernel"]:
                # These kernels are installed but none is the one running: judging them would be wrong
                g.update(state="no_data", installed=kernels[0][1], binaries=sorted({i[0] for i in kernels}),
                         note=f"installed but not running (running: {g['kernel']}): check the running kernel by hand",
                         fixed=None, advisory=rule["advisory"] if rule else "", via=rule["via"] if rule else "")
                g.pop("kernel")
                out.append(g)
                continue
            else:
                note = "running kernel unknown: all installed kernels are compared"
        g.pop("kernel")
        third = [i for i in items if i[4]]
        if third and len(third) == len(items):
            built_by = third[0][5] or ""
            # The software vendor's ranges first (CVE.org / NVD), then Ubuntu's upstream fixed version
            product = next((eol.product_for(n) for n in [g["package"], *[i[0] for i in third]]
                            if eol.product_for(n)), None)
            verdict = vendor_verdict(vendor, product, third[0][1]) if vendor and product else None
            if verdict:
                state, fixed, via = verdict
            else:
                state, fixed = _upstream_estimate(idx, g["package"], [i[0] for i in third], third[0][1])
                via = "upstream (Ubuntu)" if state != "third_party" else ""
            advisory = ""
            # Debian/Ubuntu: the "built by" field is only a hint (many distribution packages keep a personal
            # maintainer), so the distribution's verdict is also computed and the worse of both is kept
            if rule and third[0][2] == "deb":
                distro = _state(rule, third[0][1], "deb")
                if STATES.index(distro) < STATES.index(state):
                    state, via, advisory = distro, rule["via"], rule["advisory"]
                    fixed = _fixed_for(rule, third[0][1], "deb") if rule["state"] == "fixed" else None
            g.update(state=state, installed=third[0][1], binaries=sorted({i[0] for i in items}),
                     note=f"built by {built_by}" if built_by else "", fixed=fixed, advisory=advisory, via=via)
            out.append(g)
            continue
        items = [i for i in items if not i[4]]
        if not note and any(i[5] is None and i[2] in ("rpm", "deb") for i in items):
            note = "who built it is unknown until the server is scanned again (it could be a third-party package)"
        worst = None
        for name, version, source, *_ in items:
            st = _state(rule, version, source)
            if worst is None or STATES.index(st) < STATES.index(worst[0]):
                worst = (st, version, source)
        fixed = (_fixed_for(rule, worst[1], "rpm" if worst[2] == "rpm" else "deb")
                 if rule and rule["state"] == "fixed" else None)
        g.update(state=worst[0], installed=worst[1], binaries=sorted({i[0] for i in items}), note=note,
                 fixed=fixed, advisory=rule["advisory"] if rule else "", via=rule["via"] if rule else "")
        out.append(g)
    out.sort(key=lambda g: (STATES.index(g["state"]), g["server"] or "", g["container"] or ""))
    return out

# ---------- the software's own vendor (CVE.org record and NVD) ----------
# Used for packages built by a third party (nginx.org, Docker...) and for software installed by hand (found by
# the version probes): they follow the project's own numbering, so the vendor's version ranges apply directly.

# Version probe -> endoflife.date product
PROBE_PRODUCTS = {"apache httpd": "apache-http-server", "apache2": "apache-http-server", "nginx": "nginx",
                  "openssl": "openssl", "openssh": "openssh", "node": "nodejs", "php": "php",
                  "postgresql": "postgresql", "psql": "postgresql", "redis": "redis", "mongodb": "mongodb",
                  "haproxy": "haproxy", "docker": "docker-engine", "podman": "podman", "kubelet": "kubernetes",
                  "git": "git", "curl": "curl", "sudo": "sudo", "python3": "python"}


# Packages (shell-style patterns) that install the program each probe runs. A probe counts as software
# installed by hand only when none of these is installed on that server/container.
PROBE_PACKAGES = {
    "apache httpd": ["httpd", "httpd-core", "apache2", "apache2-bin", "httpd24*"], "apache2": ["apache2*", "httpd*"],
    "nginx": ["nginx*"], "openssl": ["openssl*", "libssl*"], "openssh": ["openssh*"], "node": ["nodejs*", "node"],
    "php": ["php*"], "postgresql": ["postgresql*"], "psql": ["postgresql*"], "redis": ["redis*"],
    "mongodb": ["mongodb*"], "haproxy": ["haproxy*"], "docker": ["docker*", "moby*"], "podman": ["podman*"],
    "kubelet": ["kubelet*", "kubernetes*"], "git": ["git", "git-core*"], "curl": ["curl*"], "sudo": ["sudo*"],
    "python3": ["python3*", "python*"], "glibc": ["glibc*", "libc6*", "libc-bin", "musl*"], "bash": ["bash*"],
    "java": ["java*", "*openjdk*", "*jdk*", "*jre*", "temurin*", "zulu*"],
    "mysql/mariadb": ["mysql*", "mariadb*", "percona*"],
}


def _packaged(probe, names):
    """Does some installed package provide the program this probe found?"""
    return any(fnmatch.fnmatchcase(n, pat) for pat in PROBE_PACKAGES.get(probe, [probe]) for n in names)


def _norm(text):
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


def vendor_data(fetched):
    """[{via, vendor, product, cpe, ranges: [{start, start_incl, end, end_incl, status}], default}]."""
    src = fetched["sources"]
    out = []
    cna = (src.get("cveorg") or {}).get("data") or {}
    for a in cna.get("affected") or []:
        if not isinstance(a, dict):
            continue
        ranges = []
        for v in a.get("versions") or []:
            if not isinstance(v, dict) or not v.get("version"):
                continue
            end = v.get("lessThan") or v.get("lessThanOrEqual")
            start = str(v["version"])
            if v.get("versionType") == "git" or (end not in (None, "*") and not VERSION_LIKE.search(str(end))):
                continue                     # commit hashes or texts are not versions that can be compared
            if not VERSION_LIKE.search(start) or NOT_A_VERSION.match(start):
                if end in (None, "*"):
                    continue                 # "unspecified" alone says nothing about a concrete version
                start = "0"
            ranges.append({"start": None if start in ("0", "*", "n/a") else start,
                           "start_incl": True, "end": None if end in (None, "*") else str(end),
                           "end_incl": bool(v.get("lessThanOrEqual")), "open": end == "*",
                           "exact": end is None, "status": v.get("status") or "affected"})
        cpes = [":".join(c.split(":")[3:5]) for c in a.get("cpes") or [] if str(c).startswith("cpe:2.3:")]
        out.append({"via": "CVE.org", "vendor": a.get("vendor") or "", "product": a.get("product") or "",
                    "cpe": cpes, "ranges": ranges, "default": a.get("defaultStatus") or "unknown"})
    nvd = (src.get("nvd") or {}).get("data") or {}
    by_cpe = {}
    for conf in nvd.get("configurations") or []:
        for node in (conf or {}).get("nodes") or []:
            for m in (node or {}).get("cpeMatch") or []:
                parts = str((m or {}).get("criteria") or "").split(":")
                if not m.get("vulnerable") or len(parts) < 6 or parts[2] != "a":
                    continue
                exact = parts[5] not in ("*", "-")
                version = parts[5]
                if exact and len(parts) > 6 and parts[6] not in ("*", "-", ""):
                    version += parts[6]              # cpe ...:openssh:9.3:p1 is version 9.3p1
                end = None if exact else (m.get("versionEndExcluding") or m.get("versionEndIncluding"))
                rng = {"start": version if exact else (m.get("versionStartIncluding") or m.get("versionStartExcluding")),
                       "start_incl": not m.get("versionStartExcluding"),
                       "end": end, "end_incl": bool(m.get("versionEndIncluding")),
                       "open": not exact and end is None,      # no upper bound: affected, no fix known
                       "exact": exact, "status": "affected"}
                key = f"{parts[3]}:{parts[4]}"
                by_cpe.setdefault(key, {"via": "NVD", "vendor": parts[3], "product": parts[4], "cpe": [key],
                                        "ranges": [], "default": "unaffected"})["ranges"].append(rng)
    return out + list(by_cpe.values())


# What a vendor entry must match: CPE "vendor:product" ids and normalised names
def _subject_for_product(product):
    info = eol.product_info(product)
    names = {_norm(product), _norm(info["label"])} | {_norm(c.split(":")[-1]) for c in info["cpe"]}
    names |= {_norm(probe) for probe, p in PROBE_PRODUCTS.items() if p == product}    # "node" for Node.js
    return {"cpe": set(info["cpe"]), "names": names - {""}}


# Programs whose output says who made them: each maker has its own product at the vendor
VARIANT_SUBJECTS = {
    ("java", "Oracle"): ({"oracle:jdk", "oracle:jre"}, {"javase", "oraclejavase", "jdk", "jre"}),
    ("java", "OpenJDK"): ({"oracle:openjdk", "oracle:jdk", "oracle:jre"}, {"openjdk", "javase", "oraclejavase"}),
    ("mysql/mariadb", "MySQL"): ({"oracle:mysql", "oracle:mysql_server"}, {"mysql", "mysqlserver"}),
    ("mysql/mariadb", "MariaDB"): ({"mariadb:mariadb"}, {"mariadb", "mariadbserver"}),
}


def _subject_for_probe(name, variant, cpe):
    """Subject of a version probe: its maker when the program says it, else its CPE (Settings) and its
    endoflife.date product."""
    for (probe, maker), (cpes, names) in VARIANT_SUBJECTS.items():
        if probe == name and (variant or "").startswith(maker):
            return {"cpe": set(cpes), "names": set(names)}
    subject = {"cpe": set(), "names": {_norm(name)}}
    if cpe:
        subject["cpe"].add(cpe.strip().lower())
        subject["names"].add(_norm(cpe.split(":")[-1]))
    if PROBE_PRODUCTS.get(name):
        extra = _subject_for_product(PROBE_PRODUCTS[name])
        subject["cpe"] |= extra["cpe"]
        subject["names"] |= extra["names"]
    subject["names"].discard("")
    return subject


def _matches(entry, subject):
    """Does a vendor entry (CVE.org product name / NVD CPE) talk about this subject?"""
    if set(entry["cpe"]) & subject["cpe"]:
        return True
    if entry["via"] == "NVD":
        return False                                   # NVD is matched by CPE only
    # Exact name, ignoring only edition words ("NGINX Open Source" = nginx). No partial matches: "Redis"
    # must not match "RedisInsight", which is another product with other versions.
    name = _norm(QUALIFIERS.sub("", str(entry["product"]).lower()))
    return bool(name) and name in subject["names"]


def _matches_product(entry, product):
    return _matches(entry, _subject_for_product(product))


QUALIFIERS = re.compile(r"\b(open[ -]?source|community( edition)?|oss|\(oss\)|oracle)\b")
NOT_A_VERSION = re.compile(r"^(unspecified|n/a|unknown|all|-)$", re.I)


def _cmp(a, b):
    return versions.compare(a, b, "deb")


def _in_range(v, r):
    if r["exact"]:
        return r["start"] is not None and _cmp(v, r["start"]) == 0
    if r["start"] and (_cmp(v, r["start"]) < 0 or (not r["start_incl"] and _cmp(v, r["start"]) == 0)):
        return False
    if r["end"]:
        c = _cmp(v, r["end"])
        return c < 0 or (r["end_incl"] and c == 0)
    return True                                        # open-ended ("affected from X on, no fix")


def java_version(v):
    """Java versions in one format: '1.8.0_401-b10', '8u511b33-perf' and NVD '1.8.0update511_b33' -> '8.0.401'
    or '8.0.511'; '17.0.11+9' -> '17.0.11'."""
    v = str(v or "").strip()
    m = re.match(r"^(?:1\.)?8(?:\.0)?(?:_|u|update)(\d+)", v)
    if m:
        return f"8.0.{m.group(1)}"
    return re.split(r"[+_\- ]", v)[0]


def _oracle_upto(e):
    """Oracle's convention: each listed version is the newest affected one of its branch ("this and earlier")."""
    affected = [r for r in e["ranges"] if r["status"] == "affected"]
    return "oracle" in str(e["vendor"]).lower() and affected and all(r["exact"] for r in affected)


def vendor_verdict(entries, product, version, subject=None, java=False):
    """(state, fixed, via) according to the software vendor, or None if it says nothing usable.
    Ranges with an upper bound go first (fixed branches); an open-ended range ("1.19.7 and later") only
    applies to versions that are not in a branch with a fix."""
    subject = subject or _subject_for_product(product)
    v = java_version(version) if java else _upstream_version(version)
    if not v or not VERSION_LIKE.search(v):
        return None
    best = None
    for e in (e for e in entries if _matches(e, subject)):
        affected = [r for r in e["ranges"] if r["status"] == "affected"]
        bounded = [r for r in affected if r["end"]]
        try:
            if _oracle_upto(e):
                depth = 1 if java else 2               # Java branches: 8, 17, 21; MySQL: 8.0, 8.4
                tops = [java_version(r["start"]) if java else r["start"] for r in affected]
                same = [t for t in tops if t.split(".")[:depth] == v.split(".")[:depth]]
                if not same:
                    continue                           # its branch is not listed: nothing said about it
                top = max(same, key=cmp_to_key(_cmp))
                verdict = (("upstream_vulnerable", f"> {top}", e["via"]) if _cmp(v, top) <= 0
                           else ("upstream_patched", None, e["via"]))
            else:
                hit = next((r for r in bounded if _in_range(v, r)), None)
                branch_fixes = [r["end"] for r in bounded if r["start"] and _cmp(v, r["start"]) >= 0
                                and r["start"].split(".")[:2] == v.split(".")[:2] and _cmp(v, r["end"]) >= 0]
                # An open range ("affected from X on") counts unless X is below the fix of this version's branch
                open_hit = any(r["open"] and _in_range(v, r) and not any(_cmp(r["start"] or "0", f) < 0
                                                                       for f in branch_fixes) for r in affected)
                if any(r["exact"] and _in_range(v, r) for r in affected):
                    verdict = ("upstream_vulnerable", None, e["via"])     # this exact version is listed
                elif hit:
                    fixed = None if hit["end_incl"] else hit["end"]
                    verdict = ("upstream_vulnerable", fixed or f"> {hit['end']}", e["via"])
                elif open_hit:
                    verdict = ("upstream_vulnerable", None, e["via"])     # affected, no fix in its branch
                elif branch_fixes:
                    verdict = ("upstream_patched", None, e["via"])        # at or above the fix of its own branch
                elif e["default"] == "unaffected" or (bounded and all(_cmp(v, r["end"]) > 0 for r in bounded)):
                    verdict = ("upstream_patched", None, e["via"])
                else:
                    continue
        except Exception:
            continue
        if (best is None or STATES.index(verdict[0]) < STATES.index(best[0])
                or (verdict[0] == best[0] and str(best[1] or "").startswith(">") and verdict[1]
                    and not str(verdict[1]).startswith(">"))):           # prefer an exact fixed version
            best = verdict
    return best


def _row(r0, container, os_name, os_ver, package, binaries, installed, state, fixed, via, note, advisory=""):
    return {"vm_id": r0["vm_id"], "server": r0["vm_name"], "host": r0["host"], "client": r0["client"],
            "environment": r0["environment"], "container": container, "image": r0["image"],
            "os": f"{os_name or ''} {os_ver or ''}".strip(), "package": package, "binaries": binaries,
            "installed": installed, "state": state, "fixed": fixed, "advisory": advisory, "via": via, "note": note}


ROW_COLUMNS = """p.vm_id, p.name, p.version, p.source, p.container, p.vendor, p.path, p.owner,
                 v.name vm_name, v.host, v.client, v.environment, v.os_id, v.os_name, v.os_version,
                 c.os_id c_os_id, c.os_name c_os_name, c.os_version c_os_version, c.image
                 FROM packages p JOIN vms v ON v.id=p.vm_id
                 LEFT JOIN containers c ON c.vm_id=p.vm_id AND c.name=p.container"""


def _os_of(r):
    if r["container"] is not None:
        return r["c_os_id"], r["c_os_name"], r["c_os_version"]
    return r["os_id"], r["os_name"], r["os_version"]


def _vendor_rows(entries, done, covered=()):
    """Rows judged with the software vendor's data (CVE.org / NVD):
    - third-party packages (nginx.org, Docker...) of the products the vendor names;
    - distribution packages of those products when the distribution has published nothing yet: "No data";
    - every copy of a program found by the version probes that no package installed (installed by hand,
      compiled into a container image, bundled inside an application), with its path."""
    out = []
    products = eol._index().get("__products__") or {}
    targets = {p for p in products if any(_matches_product(e, p) for e in entries)}
    names = [r["name"] for r in db.q("SELECT DISTINCT name FROM packages WHERE source IN ('rpm','deb','apk')")
             if eol.product_for(r["name"]) in targets] if targets else []
    if names:
        groups = {}
        for r in db.q(f"SELECT {ROW_COLUMNS} WHERE p.source IN ('rpm','deb','apk') "
                      f"AND p.name IN ({','.join('?' * len(names))})", names):
            groups.setdefault((r["vm_id"], r["container"], eol.product_for(r["name"])), []).append(r)
        for (vm_id, container, product), packages in groups.items():
            if (vm_id, container, product) in done:
                continue
            r0 = packages[0]
            os_id, os_name, os_ver = _os_of(r0)
            label = eol.product_info(product)["label"]
            third = [i for i in packages if eol.third_party(os_id, i) is True]
            if not third:
                family = _family(os_id, os_name)
                release = _release(family, os_ver)[0] if family else None
                if (family, release) not in covered:
                    # The vendor names this product but the distribution has published nothing yet for this
                    # OS version: shown as "No data" instead of leaving the server out of the result
                    out.append(_row(r0, container, os_name, os_ver, label, sorted({i["name"] for i in packages}),
                                    r0["version"], "no_data", None, "",
                                    "the distribution has not published data on this CVE yet"))
                continue                  # otherwise judged with the distribution data only
            verdict = vendor_verdict(entries, product, third[0]["version"])
            if verdict:
                out.append(_row(r0, container, os_name, os_ver, label, sorted({i["name"] for i in packages}),
                                third[0]["version"], verdict[0], verdict[1], verdict[2],
                                f"built by {third[0]['vendor']}"))

    # Version probes: every copy, judged only when no package installed that very file
    cpes = {r["name"]: r["cpe"] for r in db.q("SELECT name, cpe FROM probes")}
    probe_rows = db.q(f"SELECT {ROW_COLUMNS} WHERE p.source='probe'")
    installed = {}
    if any(r["owner"] is None for r in probe_rows):          # scans from before the owner was recorded
        for r in db.q("SELECT vm_id, container, name FROM packages WHERE source IN ('rpm','deb','apk')"):
            installed.setdefault((r["vm_id"], r["container"]), set()).add(r["name"])
    subjects = {}
    for r in probe_rows:
        key = (r["name"], (r["vendor"] or "").split(" ")[0], cpes.get(r["name"]))
        if key not in subjects:
            subjects[key] = _subject_for_probe(r["name"], r["vendor"], cpes.get(r["name"]))
        subject = subjects[key]
        if not any(_matches(e, subject) for e in entries):
            continue
        if r["owner"]:                                       # this very file belongs to a package
            continue
        if r["owner"] is None and _packaged(r["name"], installed.get((r["vm_id"], r["container"]), set())):
            continue                                         # old scan: a package seems to provide it
        product = PROBE_PRODUCTS.get(r["name"])
        if product and (r["vm_id"], r["container"], product) in done and r["owner"] is None:
            continue
        java = r["name"] == "java"
        verdict = vendor_verdict(entries, product, r["version"], subject=subject, java=java)
        if not verdict:
            continue
        os_id, os_name, os_ver = _os_of(r)
        where = r["path"] or "found by running the program"
        maker = f" · {r['vendor']}" if r["vendor"] else ""
        estimate = " (estimated with Oracle Java SE versions)" if java and (r["vendor"] or "").startswith("OpenJDK") else ""
        out.append(_row(r, r["container"], os_name, os_ver, f"{r['name']}{maker}", [r["name"]], r["version"],
                        verdict[0], verdict[1], verdict[2],
                        f"installed outside the package manager: {where}{estimate}"))
    return out

SOURCE_FAMILY = {"redhat": "rhel", "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine"}


def unevaluated(fetched):
    """[(source, servers/containers of that family)] for the distribution sources that failed: their
    servers cannot be evaluated and would otherwise just be missing from the result."""
    bad = _failed(fetched["sources"])
    failed = [(SOURCE_NAMES[name], family) for name, family in SOURCE_FAMILY.items() if name in bad]
    if not failed:
        return []
    counts = {}
    for r in db.q("SELECT os_id, os_name FROM vms WHERE last_ok_at IS NOT NULL"):
        f = _family(r["os_id"], r["os_name"])
        counts[f] = counts.get(f, 0) + 1
    for r in db.q("SELECT os_id, os_name FROM containers WHERE pkg_count IS NOT NULL"):
        f = _family(r["os_id"], r["os_name"])
        counts[f] = counts.get(f, 0) + 1
    return [(name, counts.get(family, 0)) for name, family in failed if counts.get(family)]


def missing_sources():
    """Servers scanned before the source package was recorded: their results may miss packages."""
    return db.q1("""SELECT COUNT(*) n FROM (SELECT vm_id FROM packages WHERE source IN ('rpm','deb')
                    AND container IS NULL GROUP BY vm_id HAVING COUNT(src_name)=0)""")["n"]
