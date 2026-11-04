"""File panel (SFTP) next to the terminal.

It uses the same SSH connection as the open terminal (terminal.ACTIVE), so it does not ask for
credentials again. It normally works with the login user; in "As root (sudo)" mode it starts the
system SFTP server with sudo (sudo sftp-server) over that same connection.
"""
import posixpath
import stat

import asyncssh
from asyncssh.sftp import start_sftp_client

from . import terminal

CHUNK = 256 * 1024
# Where the SFTP server usually is, depending on the distribution
FIND_SFTP_SERVER = ("for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server "
                    "/usr/libexec/sftp-server /usr/lib/sftp-server; do [ -x \"$p\" ] && echo \"$p\" && break; done")


class FilesError(Exception):
    pass


async def _root_sftp(s):
    """SFTP as root: sudo sftp-server over a channel of the same SSH connection."""
    conn = s["conn"]
    found = await conn.run(FIND_SFTP_SERVER, check=False, timeout=20)
    path = (found.stdout or "").strip()
    if not path:
        raise FilesError("sftp-server not found on the server: root mode cannot be used")
    no_password = (await conn.run("sudo -n true", check=False, timeout=20)).exit_status == 0
    command = f"sudo -n {path}" if no_password else f"sudo -S -p '' {path}"
    writer, reader, _ = await conn.open_session(command, encoding=None)
    if not no_password:
        # sudo reads the password character by character up to the newline; what follows is already SFTP
        writer.write((s.get("sudo_password") or "").encode() + b"\n")
    try:
        return await start_sftp_client(conn, conn._loop, "strict", reader, writer, "utf-8", "strict", 3)
    except (asyncssh.Error, OSError, EOFError):
        writer.close()
        raise FilesError("sudo did not allow it (wrong sudo password, or the user has no sudo rights?)")


async def client(sid, root=False):
    """(session, SFTP client) for the login user or, with root=True, as root."""
    s = terminal.ACTIVE.get(sid)
    if not s:
        raise FilesError("The terminal was closed: open it again")
    # The panel follows its terminal: a "sudo su -" (root) terminal handles files as root.
    # Decided here, from the session, never from the browser.
    root = s.get("become") == "root"
    key = "sftp_root" if root else "sftp"
    if key not in s:
        try:
            s[key] = await (_root_sftp(s) if root else s["conn"].start_sftp_client())
        except (asyncssh.Error, OSError) as e:
            raise FilesError(f"The server does not allow SFTP: {e}")
    return s, s[key]


def _err(e):
    if isinstance(e, asyncssh.SFTPPermissionDenied):
        return FilesError("Permission denied")
    if isinstance(e, asyncssh.SFTPNoSuchFile):
        return FilesError("Does not exist")
    return FilesError(str(getattr(e, "reason", e)))


async def listdir(sid, path, root=False):
    s, sftp = await client(sid, root)
    try:
        path = await sftp.realpath(path or ".")
        entries = []
        for e in await sftp.readdir(path):
            if e.filename in (".", ".."):
                continue
            a = e.attrs
            is_link = a.permissions is not None and stat.S_ISLNK(a.permissions)
            is_dir = a.permissions is not None and stat.S_ISDIR(a.permissions)
            if is_link:
                try:
                    is_dir = await sftp.isdir(posixpath.join(path, e.filename))
                except asyncssh.Error:
                    pass
            entries.append({"name": e.filename, "dir": is_dir, "link": is_link, "size": a.size or 0,
                            "mtime": a.mtime or 0,
                            "perms": stat.filemode(a.permissions) if a.permissions is not None else ""})
    except asyncssh.SFTPError as e:
        raise _err(e)
    entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    return {"path": path, "parent": posixpath.dirname(path) if path != "/" else None, "entries": entries,
            "vm": s["vm_name"]}


async def open_for_download(sid, path, root=False):
    s, sftp = await client(sid, root)
    try:
        if await sftp.isdir(path):
            raise FilesError("It is a folder: only files can be downloaded")
        f = await sftp.open(path, "rb")
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s, f


async def iter_file(f):
    try:
        while True:
            chunk = await f.read(CHUNK)
            if not chunk:
                break
            yield chunk
    finally:
        await f.close()


async def upload(sid, directory, name, upload_file, overwrite, root=False):
    s, sftp = await client(sid, root)
    name = posixpath.basename(name.replace("\\", "/"))
    if not name or name in (".", ".."):
        raise FilesError("Invalid file name")
    dest = posixpath.join(directory, name)
    try:
        if await sftp.exists(dest) and not overwrite:
            raise FilesError(f"{name} already exists")
        async with sftp.open(dest, "wb") as f:
            while True:
                chunk = await upload_file.read(CHUNK)
                if not chunk:
                    break
                await f.write(chunk)
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s, dest


async def mkdir(sid, path, root=False):
    s, sftp = await client(sid, root)
    try:
        await sftp.mkdir(path)
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s


async def delete(sid, path, root=False):
    s, sftp = await client(sid, root)
    try:
        if await sftp.isdir(path):
            await sftp.rmdir(path)  # empty folders only: never a recursive delete
        else:
            await sftp.remove(path)
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s
