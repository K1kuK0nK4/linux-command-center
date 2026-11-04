"""SSH connections to the servers.

The server fingerprint is saved the first time (TOFU). If it changes later, the connection
is refused before the password is sent, to prevent man-in-the-middle attacks.
"""
import asyncio

import asyncssh

from . import db
from .vault import vault

CONNECT_TIMEOUT = 15


class SSHError(Exception):
    pass


# Credentials typed when connecting and marked "remember": memory only, lost when the application
# is locked or restarted. They are never saved to the database.
session_auth = {}


def _stored(vm):
    cred = db.q1("SELECT * FROM credentials WHERE id=?", (vm["credential_id"],)) if vm["credential_id"] else None
    return cred


def needs(vm):
    """What is missing to connect: 'user', 'password', or None if everything is there (saved or in memory)."""
    cred = _stored(vm)
    extra = session_auth.get(vm["id"], {})
    if not ((cred and cred["username"]) or extra.get("username")):
        return "user"
    if not ((cred and (cred["password_enc"] or cred["private_key_enc"])) or extra.get("password")):
        return "password"
    return None


def resolve_auth(vm, override=None):
    """Merges what is saved with what was typed when connecting (which only fills in what is missing)."""
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
        raise SSHError("Missing user: this server does not have it saved")
    if not auth["password"] and not auth["private_key"]:
        raise SSHError("Missing password: this server does not have it saved")
    return auth


def remember(vm_id, override):
    session_auth[vm_id] = {k: v for k, v in override.items() if k in ("username", "password", "sudo_password") and v}


def sudo_password(vm, override=None):
    return resolve_auth(vm, override)["sudo_password"]


def known_hosts_key(host, port):
    """Looks up the fingerprint in the known_hosts imported in Settings (accepts hashed names and [host]:port)."""
    text = db.get_setting("known_hosts", "")
    if not text:
        return None
    try:
        keys = asyncssh.import_known_hosts(text).match(host, host, port)[0]
    except Exception:
        return None
    return keys[0].export_public_key("openssh").decode().strip() if keys else None


async def first_contact(vm, host, port, tunnel=None):
    """First contact with a server: where we get its fingerprint from.

    1. From the imported known_hosts, if it is there.
    2. Otherwise: policy "auto" = trust the first one (TOFU); "confirm" = save it as pending
       and do NOT connect (nor send credentials) until you confirm it.
    """
    known = known_hosts_key(host, port)
    if known:
        db.ex("UPDATE vms SET host_key=?, pending_host_key=NULL WHERE id=?", (known, vm["id"]))
        db.audit("hostkey_known_hosts", f"{vm['name']} ({host})")
        return known
    key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port, tunnel=tunnel, config=None), CONNECT_TIMEOUT)
    if key is None:
        raise SSHError("The server did not return a host key")
    text = key.export_public_key("openssh").decode().strip()
    fp = key.get_fingerprint("sha256")
    if db.get_setting("hostkey_policy", "confirm") == "auto":
        db.ex("UPDATE vms SET host_key=?, pending_host_key=NULL WHERE id=?", (text, vm["id"]))
        db.audit("hostkey_nueva", f"{vm['name']} ({host}) {fp}")
        return text
    db.ex("UPDATE vms SET pending_host_key=? WHERE id=?", (text, vm["id"]))
    raise SSHError(f"New fingerprint pending confirmation: {fp}. Check it and accept it on the server page "
                   "or in Inventory → Pending fingerprints.")


MAX_JUMPS = 3


async def _close_with(conn, jump):
    """When the connection to the server is closed, the bastion connection is closed too."""
    await conn.wait_closed()
    jump.close()


async def open_jump(vm, depth):
    """Connection to the bastion (another server in the inventory) that must be passed through to reach vm."""
    jump = db.q1("SELECT * FROM vms WHERE id=?", (vm["jump_vm_id"],))
    if not jump:
        raise SSHError("The configured bastion no longer exists in the inventory")
    if depth >= MAX_JUMPS:
        raise SSHError("Too many chained jumps (is a bastion pointing to another in a loop?)")
    try:
        return await connect(jump, None, depth + 1)
    except SSHError as e:
        raise SSHError(f"Bastion {jump['name']}: {e}")


async def connect(vm, override=None, depth=0):
    if not vault.unlocked:
        raise SSHError("The application is locked")
    auth = resolve_auth(vm, override)
    host, port = vm["host"], vm["port"] or 22

    client_keys = None
    if auth["private_key"]:
        try:
            client_keys = [asyncssh.import_private_key(auth["private_key"], auth["passphrase"])]
        except Exception as e:
            raise SSHError(f"Could not read the private key: {e}")

    # With a bastion, the server connection travels inside the bastion's one (like ssh -J)
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
        raise SSHError("The server key has CHANGED! Possible man-in-the-middle attack or reinstalled "
                       "server. Verify it and, if it is legitimate, press 'Accept new key' on the server page.")
    except asyncssh.PermissionDenied:
        raise SSHError("Authentication rejected (wrong user/password)")
    except (asyncio.TimeoutError, TimeoutError):
        raise SSHError("Connection timed out (IP/port correct?)")
    except ConnectionRefusedError:
        raise SSHError("Connection refused (is SSH listening on that port?)")
    except SSHError:
        raise
    except OSError as e:
        raise SSHError(f"Network error: {e}")
    except asyncssh.Error as e:
        raise SSHError(f"SSH error: {e.reason if hasattr(e, 'reason') else e}")
