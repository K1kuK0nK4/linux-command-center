"""Web terminal: bridge between the browser (xterm.js over WebSocket) and an SSH shell.

Server-to-browser messages: binary = terminal output; text = control JSON
({"t": "session", "sid": ...} for the file panel).
"""
import asyncio
import json
import re
import secrets
import time

from fastapi import WebSocket, WebSocketDisconnect

from . import db, ssh
from .i18n import _
from .ssh import SSHError, connect, sudo_password

USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
PROMPT_RE = re.compile(r"(password|contraseña|passwort|mot de passe)[^\n]*:\s*$", re.I)
# Open terminals: session id -> {"conn", "vm_id", "vm_name", "since", "become"}.
# The file panel (SFTP) reuses its SSH connection, so there is no need to authenticate again.
ACTIVE = {}


async def _say(ws, text):
    await ws.send_bytes(text.encode())


async def session(ws: WebSocket, vm_id: int, become: str | None, first_msg=None):
    vm = db.q1("SELECT * FROM vms WHERE id=?", (vm_id,))
    if not vm:
        await ws.close()
        return
    if become and not USER_RE.match(become):
        await _say(ws, f"\r\n{_('Invalid user')}\r\n")
        await ws.close()
        return

    override = None
    if ssh.needs(vm):
        # The browser first sends {"t": "auth", ...} with what the user typed
        try:
            msg = first_msg or json.loads(await asyncio.wait_for(ws.receive_text(), 300))
        except (asyncio.TimeoutError, WebSocketDisconnect, ValueError):
            await ws.close()
            return
        if msg.get("t") == "auth":
            override = {k: msg.get(k) or "" for k in ("username", "password", "sudo_password")}
            if msg.get("remember"):
                ssh.remember(vm_id, override)

    await _say(ws, _("Connecting to {n} ({h})...", n=vm["name"], h=vm["host"]) + "\r\n")
    try:
        conn = await connect(vm, override)
    except SSHError as e:
        await _say(ws, f"\r\n\x1b[31m{_(str(e))}\x1b[0m\r\n")
        await ws.close()
        return

    db.audit("terminal_abierta", f"{vm['name']} ({vm['host']})" + (f" sudo su - {become}" if become else ""))
    sid = secrets.token_urlsafe(18)
    ACTIVE[sid] = {"conn": conn, "vm_id": vm_id, "vm_name": vm["name"], "since": db.now(), "become": become,
                   # memory only: used by the file panel in "As root (sudo)" mode
                   "sudo_password": sudo_password(vm, override)}
    await ws.send_text(json.dumps({"t": "session", "sid": sid}))
    try:
        async with conn:
            proc = await conn.create_process(term_type="xterm-256color", term_size=(120, 32), encoding=None)
            pending_password = sudo_password(vm, override) if become else None
            deadline = time.monotonic() + 20
            tail = ""

            if become:
                proc.stdin.write(f"sudo su - {become}\n".encode())

            async def ssh_to_ws():
                nonlocal pending_password, tail
                while True:
                    data = await proc.stdout.read(65536)
                    if not data:
                        break
                    await ws.send_bytes(data)
                    if pending_password:
                        if time.monotonic() > deadline:
                            pending_password = None
                            continue
                        tail = (tail + data.decode("utf-8", "replace"))[-200:]
                        if PROMPT_RE.search(tail):
                            # 1) sudo flushes whatever arrives right after showing the prompt (TCSAFLUSH): wait a moment.
                            # 2) Ctrl+U clears leftovers already typed on the line (e.g. the browser's automatic reply
                            #    when the shell asks for the cursor position, "ESC[12;17R").
                            # 3) In a terminal (PTY) Enter is "\r", not "\n".
                            password, pending_password = pending_password, None
                            await asyncio.sleep(0.5)
                            proc.stdin.write(("\x15" + password + "\r").encode())

            async def ws_to_ssh():
                while True:
                    msg = json.loads(await ws.receive_text())
                    if msg.get("t") == "i":
                        proc.stdin.write(msg["d"].encode())
                    elif msg.get("t") == "r":
                        proc.change_terminal_size(int(msg["c"]), int(msg["r"]))
                    elif msg.get("t") == "danger":
                        db.audit("terminal_peligroso_confirmado", f"{vm['name']}: {msg.get('line', '')[:300]}")

            tasks = [asyncio.create_task(ssh_to_ws()), asyncio.create_task(ws_to_ssh())]
            try:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            except WebSocketDisconnect:
                pass
            finally:
                for t in tasks:
                    t.cancel()
                proc.close()
    finally:
        ACTIVE.pop(sid, None)
    db.audit("terminal_cerrada", vm["name"])
    try:
        await _say(ws, f"\r\n\x1b[33m{_('[Session closed]')}\x1b[0m\r\n")
        await ws.close()
    except Exception:
        pass
