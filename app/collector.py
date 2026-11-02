"""Escaneo de inventario sin agente.

1. Host: un único script de solo lectura por SSH (sin sudo, sin instalar nada, sin escribir en el servidor).
2. Contenedores (Docker/Podman): se listan y, en los que están en marcha, se ejecuta dentro un script
   de solo lectura para sacar su SO y paquetes. Docker suele necesitar root: se prueba sin sudo y,
   si no hay permiso, con sudo (sin contraseña o con la contraseña de sudo del servidor).
3. Sondas: "programa --version" para software instalado fuera de paquetes, en host y contenedores.
"""
import asyncio
import json
import re
import shlex

from . import db, versions
from .ssh import SSHError, connect, sudo_password

MARK = "@@@VMINV@@@ "
PROBE_MARK = "@@@P "
MAX_CONTAINERS = 40

SCRIPT_HEAD = r"""
export LC_ALL=C LANG=C
sec() { echo "@@@VMINV@@@ $1"; }
has() { command -v "$1" >/dev/null 2>&1; }
T=""; has timeout && T="timeout 10"
"""

SCRIPT = SCRIPT_HEAD + r"""
sec OSRELEASE; cat /etc/os-release 2>/dev/null
sec REDHAT; cat /etc/redhat-release 2>/dev/null
sec HOSTNAME; hostname 2>/dev/null || uname -n
sec KERNEL; uname -r
sec ARCH; uname -m
sec UPTIME; cat /proc/uptime 2>/dev/null
sec REBOOTREQ; [ -f /var/run/reboot-required ] && echo yes
if has dpkg-query; then
  sec DPKG; dpkg-query -W -f='${Status}|${Package}|${Version}|${Architecture}\n' 2>/dev/null
  sec APTHIST
  { cat /var/log/apt/history.log 2>/dev/null; zcat /var/log/apt/history.log.*.gz 2>/dev/null; } \
    | awk '/^Start-Date:/{d=$2" "$3} /^Upgrade:/{print d" U"} /^Install:/{print d" I"}' | sort -r | head -n 20
  sec DPKGMTIME; stat -c %Y /var/lib/dpkg/status 2>/dev/null
  sec APTUPG; has apt && apt list --upgradable 2>/dev/null
elif has rpm; then
  sec RPM; rpm -qa --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n' 2>/dev/null
  if has dnf; then PM=dnf; else PM=yum; fi
  sec RPMUPG; timeout 60 $PM -q -C check-update 2>/dev/null; echo "EXIT=$?"
  sec RPMSEC
  if [ "$PM" = dnf ]; then timeout 60 dnf -q -C updateinfo list --security 2>/dev/null; echo "EXIT=$?"
  else timeout 60 yum -q -C updateinfo list security 2>/dev/null; echo "EXIT=$?"; fi
elif has apk; then
  sec APK; apk info -v 2>/dev/null
fi
sec SNAP; has snap && snap list 2>/dev/null
sec PORTS; ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null
sec SERVICES; has systemctl && systemctl list-units --type=service --state=running --no-legend --no-pager --plain 2>/dev/null
"""

# Script que se ejecuta DENTRO de cada contenedor en marcha (solo lectura)
CONTAINER_SCRIPT = SCRIPT_HEAD + r"""
sec OSRELEASE; cat /etc/os-release 2>/dev/null
if has dpkg-query; then
  sec DPKG; dpkg-query -W -f='${Status}|${Package}|${Version}|${Architecture}\n' 2>/dev/null
elif has rpm; then
  sec RPM; rpm -qa --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n' 2>/dev/null
elif has apk; then
  sec APK; apk info -v 2>/dev/null
fi
"""

RPM_KERNELS = {"kernel", "kernel-core", "kernel-uek", "kernel-uek-core", "kernel-rt-core"}

# Sondas por defecto: (nombre, ejecutable, comando, expresión regular con la versión en el grupo 1)
DEFAULT_PROBES = [
    ("nginx", "nginx", "nginx -v", r"nginx/([\w.\-]+)"),
    ("apache httpd", "httpd", "httpd -v", r"Apache/([\w.\-]+)"),
    ("apache2", "apache2", "apache2 -v", r"Apache/([\w.\-]+)"),
    ("openssl", "openssl", "openssl version", r"OpenSSL ([\w.\-]+)"),
    ("openssh", "ssh", "ssh -V", r"OpenSSH_([\w.\-]+)"),
    ("java", "java", "java -version", r'version "([^"]+)"'),
    ("node", "node", "node -v", r"v(\d[\w.\-]*)"),
    ("python3", "python3", "python3 -V", r"Python ([\d.]+\w*)"),
    ("php", "php", "php -v", r"PHP ([\d.]+)"),
    ("postgresql", "postgres", "postgres --version", r"\(PostgreSQL\) ([\d.]+)"),
    ("psql", "psql", "psql --version", r"\(PostgreSQL\) ([\d.]+)"),
    ("mysql/mariadb", "mysqld", "mysqld --version", r"Ver ([\d.]+[\w.\-]*)"),
    ("redis", "redis-server", "redis-server -v", r"v=([\d.]+)"),
    ("mongodb", "mongod", "mongod --version", r"db version v([\d.]+)"),
    ("haproxy", "haproxy", "haproxy -v", r"version ([\d.]+)"),
    ("docker", "docker", "docker --version", r"version ([\d.]+)"),
    ("podman", "podman", "podman --version", r"version ([\d.]+)"),
    ("kubelet", "kubelet", "kubelet --version", r"v([\d.]+)"),
    ("sudo", "sudo", "sudo -V", r"Sudo version ([\w.]+)"),
    ("curl", "curl", "curl --version", r"curl ([\d.]+)"),
    ("glibc", "ldd", "ldd --version", r"^ldd \(.*\) (\d+\.\d+)"),
    ("bash", "bash", "bash --version", r"version ([\d.]+)"),
    ("git", "git", "git --version", r"git version ([\d.]+)"),
    ("tomcat", "catalina.sh", "catalina.sh version", r"Apache Tomcat/([\d.]+)"),
]


def seed_probes():
    if db.get_setting("probes_seeded"):
        return
    for p in DEFAULT_PROBES:
        db.ex("INSERT INTO probes(name, bin, command, regex) VALUES(?,?,?,?)", p)
    db.set_setting("probes_seeded", 1)


def active_probes():
    return db.q("SELECT * FROM probes WHERE enabled=1 ORDER BY name")


def probe_block(probes):
    """Parte del script que lanza las sondas (solo si el programa existe)."""
    lines = ["sec PROBES"]
    for p in probes:
        lines.append(f"printf '%s\\n' {shlex.quote(PROBE_MARK + p['name'])}")
        lines.append(f"if has {shlex.quote(p['bin'])}; then $T sh -c {shlex.quote(p['command'])} 2>&1 | head -n 5; fi")
    return "\n".join(lines) + "\n"


def host_script(probes):
    return SCRIPT + probe_block(probes) + "sec END\n"


def container_script(probes):
    return CONTAINER_SCRIPT + probe_block(probes) + "sec END\n"


def parse_probes(lines, probes):
    """Devuelve [(nombre, versión)] de las sondas que han respondido."""
    regex = {p["name"]: p["regex"] for p in probes}
    found, current, buf = [], None, []

    def flush():
        if current and buf and current in regex:
            try:
                m = re.search(regex[current], "\n".join(buf), re.M)
            except re.error:
                m = None
            if m and m.group(1):
                found.append((current, m.group(1)))

    for line in lines:
        if line.startswith(PROBE_MARK):
            flush()
            current, buf = line[len(PROBE_MARK):].strip(), []
        elif current:
            buf.append(line)
    flush()
    return found


def split_sections(out):
    sections, current = {}, None
    for line in out.splitlines():
        if line.startswith(MARK):
            current = line[len(MARK):].strip()
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def parse_os_release(lines):
    data = {}
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"').strip("'")
    return data


def parse_package_sections(s):
    """Paquetes de las secciones DPKG / RPM / APK. Devuelve (familia, [(nombre, versión, arq, origen)])."""
    packages = []
    if "DPKG" in s:
        for line in s["DPKG"]:
            parts = line.split("|")
            if len(parts) == 4 and parts[0].endswith(" installed"):
                packages.append((parts[1], parts[2], parts[3], "deb"))
        return "deb", packages
    if "RPM" in s:
        for line in s["RPM"]:
            parts = line.split("|")
            if len(parts) == 6:
                name, epoch, ver, rel, arch, _ = parts
                evr = f"{ver}-{rel}" if epoch in ("(none)", "", "0") else f"{epoch}:{ver}-{rel}"
                packages.append((name, evr, arch, "rpm"))
        return "rpm", packages
    if "APK" in s:
        for line in s["APK"]:
            m = re.match(r"^(.+)-(\d[^-]*-r\d+)$", line.strip())
            if m:
                packages.append((m.group(1), m.group(2), "", "apk"))
        return "apk", packages
    return "", packages


def parse_container(out, probes=()):
    s = split_sections(out)
    if "END" not in s:
        raise SSHError("El script del contenedor no terminó correctamente")
    osr = parse_os_release(s.get("OSRELEASE", []))
    family, packages = parse_package_sections(s)
    packages += [(name, ver, "", "sonda") for name, ver in parse_probes(s.get("PROBES", []), probes)]
    return {"os_name": osr.get("NAME", ""), "os_version": osr.get("VERSION_ID", ""), "os_family": family,
            "packages": packages}


def parse(out, probes=()):
    s = split_sections(out)
    if "END" not in s:
        raise SSHError("El script de inventario no terminó correctamente")
    first = lambda key: next((l.strip() for l in s.get(key, []) if l.strip()), "")

    info = {"hostname": first("HOSTNAME"), "kernel": first("KERNEL"), "arch": first("ARCH")}
    osr = parse_os_release(s.get("OSRELEASE", []))
    info["os_id"] = osr.get("ID", "")
    info["os_name"] = osr.get("NAME") or first("REDHAT")
    info["os_version"] = osr.get("VERSION_ID", "")
    if not info["os_version"] and first("REDHAT"):
        m = re.search(r"release\s+([\d.]+)", first("REDHAT"))
        info["os_version"] = m.group(1) if m else ""

    try:
        info["uptime_s"] = int(float(first("UPTIME").split()[0]))
    except (ValueError, IndexError):
        info["uptime_s"] = None

    packages = []
    info["reboot_required"] = 0
    info["last_pkg_update"] = None
    info["pending_updates"] = None
    info["pending_security"] = None

    if "DPKG" in s:
        info["os_family"] = "deb"
        for line in s["DPKG"]:
            parts = line.split("|")
            if len(parts) == 4 and parts[0].endswith(" installed"):
                packages.append((parts[1], parts[2], parts[3], "deb"))
        info["reboot_required"] = 1 if first("REBOOTREQ") == "yes" else 0
        hist = [l.strip() for l in s.get("APTHIST", []) if l.strip()]
        upgrades = [l[:-2] for l in hist if l.endswith(" U")]
        if upgrades:
            info["last_pkg_update"] = upgrades[0]
        elif hist:
            info["last_pkg_update"] = hist[0][:-2]
        elif first("DPKGMTIME").isdigit():
            info["last_pkg_update"] = db.from_epoch(first("DPKGMTIME"))
        if "APTUPG" in s:
            upg = [l for l in s["APTUPG"] if "upgradable from" in l]
            info["pending_updates"] = len(upg)
            info["pending_security"] = sum(1 for l in upg if "-security" in l.split(" ")[0])

    elif "RPM" in s:
        info["os_family"] = "rpm"
        newest_install, kernels = 0, []
        for line in s["RPM"]:
            parts = line.split("|")
            if len(parts) != 6:
                continue
            name, epoch, ver, rel, arch, itime = parts
            evr = f"{ver}-{rel}" if epoch in ("(none)", "", "0") else f"{epoch}:{ver}-{rel}"
            packages.append((name, evr, arch, "rpm"))
            if itime.isdigit():
                newest_install = max(newest_install, int(itime))
            if name in RPM_KERNELS:
                kernels.append(f"{ver}-{rel}")
        if newest_install:
            info["last_pkg_update"] = db.from_epoch(newest_install)
        if kernels:
            latest = kernels[0]
            for k in kernels[1:]:
                if versions.rpm_compare(k, latest) > 0:
                    latest = k
            info["reboot_required"] = 0 if info["kernel"].startswith(latest) else 1
        info["pending_updates"] = _parse_rpm_updates(s.get("RPMUPG", []))
        info["pending_security"] = _parse_rpm_security(s.get("RPMSEC", []))
    elif "APK" in s:
        info["os_family"], packages = parse_package_sections(s)
    else:
        info["os_family"] = ""

    for line in s.get("SNAP", [])[1:]:
        parts = line.split()
        if len(parts) >= 2:
            packages.append((parts[0], parts[1], "", "snap"))

    if info["kernel"]:
        packages.append(("kernel-running", info["kernel"], info["arch"], "kernel"))
    packages += [(name, ver, "", "sonda") for name, ver in parse_probes(s.get("PROBES", []), probes)]

    ports = set()
    for line in s.get("PORTS", []):
        t = line.split()
        if len(t) < 5 or not (t[0].startswith("tcp") or t[0].startswith("udp")):
            continue
        local = t[3] if t[1].isdigit() else t[4]
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        if port.isdigit():
            ports.add((t[0][:3], addr.strip("[]"), int(port)))

    services = []
    for line in s.get("SERVICES", []):
        t = line.split()
        if t and t[0].endswith(".service"):
            services.append(t[0][:-8])

    return info, packages, sorted(ports, key=lambda p: (p[2], p[0])), services


def _exit_code(lines):
    for l in lines:
        if l.startswith("EXIT="):
            return int(l[5:]) if l[5:].isdigit() else None
    return None


def _parse_rpm_updates(lines):
    code = _exit_code(lines)
    if code == 0:
        return 0
    if code != 100:
        return None
    count = 0
    for l in lines:
        if l.startswith("Obsoleting"):
            break
        t = l.split()
        if len(t) == 3 and "." in t[0] and not l.startswith("EXIT="):
            count += 1
    return count


def _parse_rpm_security(lines):
    if _exit_code(lines) != 0:
        return None
    pkgs = {l.split()[2] for l in lines if len(l.split()) >= 3 and not l.startswith("EXIT=")}
    return len(pkgs)


def save(vm_id, started_at, info, packages, ports, services, containers=None, containers_error=None):
    """packages: paquetes del host [(nombre, versión, arq, origen)]; containers: [{..., "packages": [...]}]."""
    rows = [(n, v, a, src, None) for n, v, a, src in packages]
    for ct in containers or []:
        rows += [(n, v, a, src, ct["name"]) for n, v, a, src in ct.get("packages", [])]
    old = {(r["name"], r["arch"], r["source"], r["container"]): r["version"]
           for r in db.q("SELECT name, version, arch, source, container FROM packages WHERE vm_id=?", (vm_id,))}
    new = {(n, a, src, ct): v for n, v, a, src, ct in rows}
    changes = []
    if old:
        for k, v in new.items():
            if k not in old:
                changes.append((k[0], None, v, "añadido", k[3]))
            elif old[k] != v:
                changes.append((k[0], old[k], v, "actualizado", k[3]))
        for k, v in old.items():
            if k not in new:
                changes.append((k[0], v, None, "eliminado", k[3]))

    ts = db.now()
    count = sum(1 for p in packages if p[3] not in ("kernel", "sonda"))
    with db.tx() as c:
        c.execute("DELETE FROM packages WHERE vm_id=?", (vm_id,))
        c.executemany("INSERT INTO packages(vm_id, name, version, arch, source, container) VALUES(?,?,?,?,?,?)",
                      [(vm_id, *r) for r in rows])
        c.execute("DELETE FROM containers WHERE vm_id=?", (vm_id,))
        c.executemany("""INSERT INTO containers(vm_id, runtime, cid, name, image, state, status, ports, os_name,
                         os_version, os_family, pkg_count, error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      [(vm_id, ct["runtime"], ct["cid"], ct["name"], ct["image"], ct["state"], ct["status"],
                        ct["ports"], ct.get("os_name"), ct.get("os_version"), ct.get("os_family"),
                        len([p for p in ct.get("packages", []) if p[3] != "sonda"]) if ct.get("packages") else None,
                        ct.get("error")) for ct in containers or []])
        c.execute("UPDATE vms SET container_count=?, containers_error=? WHERE id=?",
                  (len(containers) if containers is not None else None, containers_error, vm_id))
        c.execute("DELETE FROM ports WHERE vm_id=?", (vm_id,))
        c.executemany("INSERT INTO ports(vm_id, proto, address, port) VALUES(?,?,?,?)",
                      [(vm_id, *p) for p in ports])
        c.execute("DELETE FROM services WHERE vm_id=?", (vm_id,))
        c.executemany("INSERT INTO services(vm_id, name) VALUES(?,?)", [(vm_id, n) for n in services])
        c.execute("""UPDATE vms SET hostname=?, os_id=?, os_name=?, os_version=?, os_family=?, kernel=?,
                     arch=?, uptime_s=?, reboot_required=?, pending_updates=?, pending_security=?,
                     last_pkg_update=?, pkg_count=?, last_scan_at=?, last_ok_at=?,
                     last_scan_status='ok', last_scan_error=NULL WHERE id=?""",
                  (info["hostname"], info["os_id"], info["os_name"], info["os_version"], info["os_family"],
                   info["kernel"], info["arch"], info["uptime_s"], info["reboot_required"],
                   info["pending_updates"], info["pending_security"], info["last_pkg_update"], count,
                   ts, ts, vm_id))
        scan_id = c.execute("""INSERT INTO scan_history(vm_id, started_at, finished_at, status, pkg_count,
                               added, removed, changed) VALUES(?,?,?,?,?,?,?,?)""",
                            (vm_id, started_at, ts, "ok", count,
                             sum(1 for ch in changes if ch[3] == "añadido"),
                             sum(1 for ch in changes if ch[3] == "eliminado"),
                             sum(1 for ch in changes if ch[3] == "actualizado"))).lastrowid
        c.executemany("INSERT INTO package_changes(scan_id, vm_id, name, old_version, new_version, change, container) "
                      "VALUES(?,?,?,?,?,?,?)", [(scan_id, vm_id, *ch) for ch in changes])
    db.bump()


def save_error(vm_id, started_at, error):
    ts = db.now()
    with db.tx() as c:
        c.execute("UPDATE vms SET last_scan_at=?, last_scan_status='error', last_scan_error=? WHERE id=?",
                  (ts, error, vm_id))
        c.execute("INSERT INTO scan_history(vm_id, started_at, finished_at, status, error) VALUES(?,?,?,?,?)",
                  (vm_id, started_at, ts, "error", error))
    db.bump()


def parse_ps(runtime, out):
    """Docker devuelve una línea JSON por contenedor; Podman, un array JSON."""
    text = (out or "").strip()
    if not text:
        return []
    data = json.loads(text) if text.startswith("[") else \
        [json.loads(line) for line in text.splitlines() if line.strip().startswith("{")]
    items = []
    for d in data:
        names = d.get("Names") or ""
        if isinstance(names, list):
            names = ",".join(names)
        ports = d.get("Ports") or ""
        if isinstance(ports, list):
            ports = ", ".join(f"{p.get('host_ip') or '0.0.0.0'}:{p.get('host_port')}->{p.get('container_port')}/"
                              f"{p.get('protocol', 'tcp')}" for p in ports if isinstance(p, dict))
        items.append({"runtime": runtime, "cid": str(d.get("ID") or d.get("Id") or "")[:12],
                      "name": names.lstrip("/"), "image": d.get("Image") or "",
                      "state": str(d.get("State") or "").lower(), "status": d.get("Status") or "",
                      "ports": ports})
    return items


async def _runtime_access(conn, runtime, vm, override):
    """Cómo hablar con Docker/Podman: sin sudo, con sudo sin contraseña o con la contraseña de sudo.

    Devuelve (prefijo, entrada estándar) o (None, None) si no hay permiso.
    """
    r = await conn.run(f"{runtime} ps -q", check=False, timeout=30)
    if r.exit_status == 0:
        return "", None
    r = await conn.run(f"sudo -n {runtime} ps -q", check=False, timeout=30)
    if r.exit_status == 0:
        return "sudo -n ", None
    try:
        pw = sudo_password(vm, override)
    except SSHError:
        pw = ""
    if pw:
        r = await conn.run(f"sudo -S -p '' {runtime} ps -q", input=pw + "\n", check=False, timeout=30)
        if r.exit_status == 0:
            return "sudo -S -p '' ", pw + "\n"
    return None, None


async def scan_containers(conn, vm, override, probes):
    """Devuelve (contenedores, error). contenedores = None si el servidor no tiene Docker ni Podman."""
    r = await conn.run("for r in docker podman; do command -v $r >/dev/null 2>&1 && echo $r; done",
                       check=False, timeout=20)
    runtimes = [l.strip() for l in (r.stdout or "").splitlines() if l.strip() in ("docker", "podman")]
    if not runtimes:
        return None, None
    containers, errors = [], []
    script = container_script(probes)
    for rt in runtimes:
        prefix, stdin = await _runtime_access(conn, rt, vm, override)
        if prefix is None:
            errors.append(f"{rt}: sin permiso (el usuario no está en el grupo {rt} y sudo no funciona) "
                          "o el servicio no está arrancado")
            continue
        if prefix:
            db.audit("contenedores_sudo", f"{vm['name']}: {rt} con sudo (solo lectura)")
        fmt = "--format json" if rt == "podman" else "--format '{{json .}}'"
        ps = await conn.run(f"{prefix}{rt} ps -a --no-trunc {fmt}", input=stdin, check=False, timeout=60,
                            encoding="utf-8", errors="replace")
        if ps.exit_status != 0:
            err_lines = (ps.stderr or "").strip().splitlines()
            errors.append(f"{rt}: {err_lines[-1] if err_lines else 'error al listar contenedores'}")
            continue
        try:
            items = parse_ps(rt, ps.stdout)
        except ValueError:
            errors.append(f"{rt}: no se entiende la salida de '{rt} ps'")
            continue
        if len(items) > MAX_CONTAINERS:
            errors.append(f"{rt}: solo se inventarían los primeros {MAX_CONTAINERS} contenedores")
        for ct in items[:MAX_CONTAINERS]:
            if ct["state"] != "running":
                ct["error"] = "Parado: solo se inventarían los contenedores en marcha"
                continue
            try:
                ex = await conn.run(f"{prefix}{rt} exec {shlex.quote(ct['cid'])} sh -c {shlex.quote(script)}",
                                    input=stdin, check=False, timeout=90, encoding="utf-8", errors="replace")
                if MARK + "END" not in (ex.stdout or ""):
                    ct["error"] = "No se pudo inspeccionar (¿imagen sin shell, tipo distroless?)"
                else:
                    ct.update(parse_container(ex.stdout, probes))
            except (asyncio.TimeoutError, TimeoutError):
                ct["error"] = "Tiempo agotado al inspeccionar el contenedor"
        containers += items[:MAX_CONTAINERS]
    return containers, "; ".join(errors) or None


async def scan_vm(vm_id, override=None):
    vm = db.q1("SELECT * FROM vms WHERE id=?", (vm_id,))
    if not vm:
        return
    started = db.now()
    probes = active_probes()
    try:
        async with await connect(vm, override) as conn:
            result = await conn.run("/bin/sh -s", input=host_script(probes), check=False, timeout=180,
                                    encoding="utf-8", errors="replace")
            info, packages, ports, services = parse(result.stdout or "", probes)
            # Un fallo con los contenedores no estropea el inventario del host
            try:
                containers, containers_error = await scan_containers(conn, vm, override, probes)
            except Exception as e:
                containers, containers_error = [], f"Error al revisar contenedores: {type(e).__name__}: {e}"
        save(vm_id, started, info, packages, ports, services, containers, containers_error)
    except SSHError as e:
        save_error(vm_id, started, str(e))
    except (asyncio.TimeoutError, TimeoutError):
        save_error(vm_id, started, "El escaneo tardó más de 3 minutos")
    except Exception as e:
        save_error(vm_id, started, f"{type(e).__name__}: {e}")


# ---------- cola de escaneos ----------

running = {}
_tasks = set()
_sem = None
_sem_size = None


def _semaphore():
    global _sem, _sem_size
    size = int(db.get_setting("scan_concurrency", 15))
    if _sem is None or size != _sem_size:
        _sem, _sem_size = asyncio.Semaphore(size), size
    return _sem


async def _scan_task(vm_id, override):
    try:
        async with _semaphore():
            running[vm_id] = "running"
            await scan_vm(vm_id, override)
    finally:
        running.pop(vm_id, None)


def start_scans(vm_ids, overrides=None):
    """overrides: {vm_id: {username, password, sudo_password}} tecleados al lanzar (no se guardan)."""
    started = 0
    for vm_id in vm_ids:
        if vm_id in running:
            continue
        running[vm_id] = "queued"
        t = asyncio.create_task(_scan_task(vm_id, (overrides or {}).get(vm_id)))
        _tasks.add(t)
        t.add_done_callback(_tasks.discard)
        started += 1
    return started
