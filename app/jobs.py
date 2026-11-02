"""Ejecución masiva de comandos en varios servidores a la vez."""
import asyncio
import shlex

from . import db
from .ssh import SSHError, connect, sudo_password

MAX_OUTPUT = 200_000
_tasks = set()


def create_job(vm_ids, command, use_sudo, timeout_s, overrides=None):
    vms = db.q(f"SELECT id, name FROM vms WHERE id IN ({','.join('?' * len(vm_ids))})", vm_ids)
    job_id = db.ex("INSERT INTO jobs(command, use_sudo, timeout_s, created_at, target_count) VALUES(?,?,?,?,?)",
                   (command, 1 if use_sudo else 0, timeout_s, db.now(), len(vms)))
    with db.tx() as c:
        c.executemany("INSERT INTO job_results(job_id, vm_id, vm_name, status) VALUES(?,?,?,'pendiente')",
                      [(job_id, v["id"], v["name"]) for v in vms])
    db.audit("comando_masivo", f"ejecución #{job_id} en {len(vms)} servidores{' con sudo' if use_sudo else ''}: {command}")
    t = asyncio.create_task(_run_job(job_id, [v["id"] for v in vms], command, use_sudo, timeout_s, overrides or {}))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    return job_id


async def _run_job(job_id, vm_ids, command, use_sudo, timeout_s, overrides):
    sem = asyncio.Semaphore(int(db.get_setting("command_concurrency", 20)))

    async def one(vm_id):
        async with sem:
            await _run_one(job_id, vm_id, command, use_sudo, timeout_s, overrides.get(vm_id))

    await asyncio.gather(*(one(v) for v in vm_ids), return_exceptions=True)
    db.ex("UPDATE jobs SET finished_at=? WHERE id=?", (db.now(), job_id))


def _set(job_id, vm_id, **fields):
    cols = ", ".join(f"{k}=?" for k in fields)
    db.ex(f"UPDATE job_results SET {cols} WHERE job_id=? AND vm_id=?", (*fields.values(), job_id, vm_id))


async def _run_one(job_id, vm_id, command, use_sudo, timeout_s, override=None):
    _set(job_id, vm_id, status="ejecutando", started_at=db.now())
    vm = db.q1("SELECT * FROM vms WHERE id=?", (vm_id,))
    try:
        async with await connect(vm, override) as conn:
            stdin = None
            full = command
            if use_sudo:
                probe = await conn.run("sudo -n true", check=False, timeout=20)
                if probe.exit_status == 0:
                    full = "sudo -n -- sh -c " + shlex.quote(command)
                else:
                    full = "sudo -S -p '' -- sh -c " + shlex.quote(command)
                    stdin = sudo_password(vm, override) + "\n"
            r = await conn.run(full, input=stdin, check=False, timeout=timeout_s,
                               encoding="utf-8", errors="replace")
        code = r.exit_status
        _set(job_id, vm_id, status="ok" if code == 0 else "fallo", exit_code=code,
             stdout=(r.stdout or "")[:MAX_OUTPUT], stderr=(r.stderr or "")[:MAX_OUTPUT], finished_at=db.now())
    except SSHError as e:
        _set(job_id, vm_id, status="error", stderr=str(e), finished_at=db.now())
    except (asyncio.TimeoutError, TimeoutError):
        _set(job_id, vm_id, status="error", stderr=f"Tiempo agotado ({timeout_s}s)", finished_at=db.now())
    except Exception as e:
        _set(job_id, vm_id, status="error", stderr=f"{type(e).__name__}: {e}", finished_at=db.now())
