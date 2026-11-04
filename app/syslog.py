"""Sends the audit log to a SIEM or syslog server (RFC 5424 over UDP)."""
import json
import socket
from datetime import datetime

from . import db

_target = None
_sock = None


def configure(target):
    """target: 'host:port', or empty to disable."""
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
            pass  # sending must never stop the application from working


db.audit_listeners.append(send)
