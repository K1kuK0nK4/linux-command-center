"""Conexión SSH a los servidores.

La huella del servidor se guarda la primera vez (TOFU). Si después cambia, se rechaza
la conexión antes de enviar la contraseña, para evitar ataques de intermediario.
"""
import asyncio

import asyncssh

from . import db
from .vault import vault

CONNECT_TIMEOUT = 15


class SSHError(Exception):
    pass


# Credenciales tecleadas al conectar y marcadas como "recordar": solo en memoria, se pierden al
# bloquear la aplicación o reiniciarla. Nunca se guardan en la base de datos.
session_auth = {}


def _stored(vm):
    cred = db.q1("SELECT * FROM credentials WHERE id=?", (vm["credential_id"],)) if vm["credential_id"] else None
    return cred


def needs(vm):
    """Qué falta para conectar: 'user', 'password' o None si está todo (guardado o en memoria)."""
    cred = _stored(vm)
    extra = session_auth.get(vm["id"], {})
    if not ((cred and cred["username"]) or extra.get("username")):
        return "user"
    if not ((cred and (cred["password_enc"] or cred["private_key_enc"])) or extra.get("password")):
        return "password"
    return None


def resolve_auth(vm, override=None):
    """Combina lo guardado con lo tecleado al conectar (que solo rellena lo que falta)."""
    cred = _stored(vm)
    extra = {**session_auth.get(vm["id"], {}), **{k: v for k, v in (override or {}).items() if v}}
    stored_pw = vault.decrypt(cred["password_enc"]) if cred else None
    auth = {
        "username": (cred["username"] if cred else None) or extra.get("username"),
        "password": stored_pw or extra.get("password"),
        "private_key": vault.decrypt(cred["private_key_enc"]) if cred else None,
        "passphrase": vault.decrypt(cred["key_passphrase_enc"]) if cred else None,
    }
    auth["sudo_password"] = ((vault.decrypt(cred["sudo_password_enc"]) if cred else None)
                             or extra.get("sudo_password") or auth["password"] or "")
    if not auth["username"]:
        raise SSHError("Falta el usuario: este servidor no lo tiene guardado")
    if not auth["password"] and not auth["private_key"]:
        raise SSHError("Falta la contraseña: este servidor no la tiene guardada")
    return auth


def remember(vm_id, override):
    session_auth[vm_id] = {k: v for k, v in override.items() if k in ("username", "password", "sudo_password") and v}


def sudo_password(vm, override=None):
    return resolve_auth(vm, override)["sudo_password"]


def known_hosts_key(host, port):
    """Busca la huella en el known_hosts importado en Ajustes (admite nombres hasheados y [host]:puerto)."""
    text = db.get_setting("known_hosts", "")
    if not text:
        return None
    try:
        keys = asyncssh.import_known_hosts(text).match(host, host, port)[0]
    except Exception:
        return None
    return keys[0].export_public_key("openssh").decode().strip() if keys else None


async def first_contact(vm, host, port, tunnel=None):
    """Primera conexión con un servidor: de dónde sacamos su huella.

    1. Del known_hosts importado, si está ahí.
    2. Si no: política "auto" = confiar en la primera (TOFU); "confirm" = guardarla como pendiente
       y NO conectar (ni enviar credenciales) hasta que la confirmes.
    """
    known = known_hosts_key(host, port)
    if known:
        db.ex("UPDATE vms SET host_key=?, pending_host_key=NULL WHERE id=?", (known, vm["id"]))
        db.audit("hostkey_known_hosts", f"{vm['name']} ({host})")
        return known
    key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port, tunnel=tunnel, config=None), CONNECT_TIMEOUT)
    if key is None:
        raise SSHError("El servidor no devolvió clave de host")
    text = key.export_public_key("openssh").decode().strip()
    fp = key.get_fingerprint("sha256")
    if db.get_setting("hostkey_policy", "confirm") == "auto":
        db.ex("UPDATE vms SET host_key=?, pending_host_key=NULL WHERE id=?", (text, vm["id"]))
        db.audit("hostkey_nueva", f"{vm['name']} ({host}) {fp}")
        return text
    db.ex("UPDATE vms SET pending_host_key=? WHERE id=?", (text, vm["id"]))
    raise SSHError(f"Huella nueva pendiente de confirmar: {fp}. Compruébala y acéptala en la ficha del servidor "
                   "o en Inventario → Huellas pendientes.")


MAX_JUMPS = 3


async def _close_with(conn, jump):
    """Cuando se cierra la conexión con el servidor, se cierra también la del bastión."""
    await conn.wait_closed()
    jump.close()


async def open_jump(vm, depth):
    """Conexión con el bastión (otro servidor del inventario) por el que hay que pasar para llegar a vm."""
    jump = db.q1("SELECT * FROM vms WHERE id=?", (vm["jump_vm_id"],))
    if not jump:
        raise SSHError("El bastión configurado ya no existe en el inventario")
    if depth >= MAX_JUMPS:
        raise SSHError("Demasiados saltos encadenados (¿un bastión apunta a otro en bucle?)")
    try:
        return await connect(jump, None, depth + 1)
    except SSHError as e:
        raise SSHError(f"Bastión {jump['name']}: {e}")


async def connect(vm, override=None, depth=0):
    if not vault.unlocked:
        raise SSHError("La aplicación está bloqueada")
    auth = resolve_auth(vm, override)
    host, port = vm["host"], vm["port"] or 22

    client_keys = None
    if auth["private_key"]:
        try:
            client_keys = [asyncssh.import_private_key(auth["private_key"], auth["passphrase"])]
        except Exception as e:
            raise SSHError(f"No se pudo leer la clave privada: {e}")

    # Con bastión, la conexión al servidor viaja dentro de la del bastión (como ssh -J)
    jump = await open_jump(vm, depth) if vm["jump_vm_id"] else None
    try:
        conn = await _connect(vm, host, port, auth, client_keys, jump)
    except BaseException:
        if jump:
            jump.close()
        raise
    if jump:
        task = asyncio.get_running_loop().create_task(_close_with(conn, jump))
        _closers.add(task)
        task.add_done_callback(_closers.discard)
    return conn


_closers = set()


async def _connect(vm, host, port, auth, client_keys, jump):
    try:
        stored = vm["host_key"] or await first_contact(vm, host, port, jump)
        trusted = asyncssh.import_public_key(stored)

        return await asyncio.wait_for(asyncssh.connect(
            host, port,
            tunnel=jump,
            username=auth["username"],
            password=auth["password"],
            client_keys=client_keys,
            agent_path=None,
            known_hosts=([trusted], [], []),
            config=None,
            login_timeout=CONNECT_TIMEOUT,
            keepalive_interval=30,
        ), CONNECT_TIMEOUT * 2)
    except asyncssh.HostKeyNotVerifiable:
        raise SSHError("¡La clave del servidor ha CAMBIADO! Posible ataque de intermediario o servidor "
                       "reinstalado. Verifícalo y, si es legítimo, pulsa 'Aceptar nueva clave' en la ficha del servidor.")
    except asyncssh.PermissionDenied:
        raise SSHError("Autenticación rechazada (usuario/contraseña incorrectos)")
    except (asyncio.TimeoutError, TimeoutError):
        raise SSHError("Tiempo de conexión agotado (¿VPN conectada? ¿IP/puerto correctos?)")
    except ConnectionRefusedError:
        raise SSHError("Conexión rechazada (¿SSH escucha en ese puerto?)")
    except SSHError:
        raise
    except OSError as e:
        raise SSHError(f"Error de red: {e}")
    except asyncssh.Error as e:
        raise SSHError(f"Error SSH: {e.reason if hasattr(e, 'reason') else e}")
