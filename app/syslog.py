"""Envío de la auditoría a un SIEM o servidor syslog (RFC 5424 sobre UDP)."""
import json
import socket
from datetime import datetime

from . import db

_target = None
_sock = None


def configure(target):
    """target: 'host:puerto' o vacío para desactivar."""
    global _target, _sock
    _target = None
    if _sock:
        _sock.close()
        _sock = None
    if not target:
        return
    host, _, port = target.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("Formato esperado host:puerto")
    _target = (host.strip("[]"), int(port))
    _sock = socket.socket(socket.AF_INET6 if ":" in _target[0] else socket.AF_INET, socket.SOCK_DGRAM)
    _sock.setblocking(False)


def message(ts, action, detail, digest):
    stamp = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=db.TZ).isoformat()
    body = json.dumps({"action": action, "detail": detail, "hash": digest}, ensure_ascii=False)
    # PRI 86 = authpriv.info
    return f"<86>1 {stamp} linux-command-center lcc - audit - {body}".encode()


def send(ts, action, detail, digest):
    if _target and _sock:
        try:
            _sock.sendto(message(ts, action, detail, digest), _target)
        except OSError:
            pass  # el envío nunca debe impedir que la aplicación funcione


db.audit_listeners.append(send)
