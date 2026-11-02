"""Panel de ficheros (SFTP) junto a la terminal.

Usa la misma conexión SSH de la terminal abierta (terminal.ACTIVE), así que no vuelve a pedir
credenciales y trabaja con el mismo usuario de login (no con el de "sudo su -").
"""
import posixpath
import stat

import asyncssh

from . import terminal

CHUNK = 256 * 1024


class FilesError(Exception):
    pass


async def client(sid):
    s = terminal.ACTIVE.get(sid)
    if not s:
        raise FilesError("La terminal se ha cerrado: vuelve a abrirla")
    if "sftp" not in s:
        try:
            s["sftp"] = await s["conn"].start_sftp_client()
        except (asyncssh.Error, OSError) as e:
            raise FilesError(f"El servidor no permite SFTP: {e}")
    return s


def _err(e):
    if isinstance(e, asyncssh.SFTPPermissionDenied):
        return FilesError("Permiso denegado")
    if isinstance(e, asyncssh.SFTPNoSuchFile):
        return FilesError("No existe")
    return FilesError(str(getattr(e, "reason", e)))


async def listdir(sid, path):
    s = await client(sid)
    sftp = s["sftp"]
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


async def open_for_download(sid, path):
    s = await client(sid)
    try:
        if await s["sftp"].isdir(path):
            raise FilesError("Es una carpeta: solo se pueden descargar ficheros")
        f = await s["sftp"].open(path, "rb")
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


async def upload(sid, directory, name, upload_file, overwrite):
    s = await client(sid)
    name = posixpath.basename(name.replace("\\", "/"))
    if not name or name in (".", ".."):
        raise FilesError("Nombre de fichero no válido")
    dest = posixpath.join(directory, name)
    sftp = s["sftp"]
    try:
        if await sftp.exists(dest) and not overwrite:
            raise FilesError(f"Ya existe {name}")
        async with sftp.open(dest, "wb") as f:
            while True:
                chunk = await upload_file.read(CHUNK)
                if not chunk:
                    break
                await f.write(chunk)
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s, dest


async def mkdir(sid, path):
    s = await client(sid)
    try:
        await s["sftp"].mkdir(path)
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s


async def delete(sid, path):
    s = await client(sid)
    sftp = s["sftp"]
    try:
        if await sftp.isdir(path):
            await sftp.rmdir(path)  # solo carpetas vacías: nunca borrado recursivo
        else:
            await sftp.remove(path)
    except asyncssh.SFTPError as e:
        raise _err(e)
    return s
