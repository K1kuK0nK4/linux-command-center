"""Exportación completa portable (.lcc): JSON comprimido y cifrado con una contraseña elegida al exportar."""
import gzip
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vault import CURRENT_LOG_N, LEGACY_LOG_N, derive

# LCC1: scrypt N=2^15 (versiones antiguas, solo lectura). LCC2: un byte con log2(N) tras la marca.
MAGIC = b"LCC2"
MAGIC_V1 = b"LCC1"
FORMAT = "linux-command-center-export"

SECTIONS = {
    "vms": "Servidores (con su usuario/contraseña propios y etiquetas)",
    "credentials": "Credenciales compartidas",
    "organization": "Clientes, entornos y etiquetas",
    "commands": "Comandos guardados",
    "charts": "Gráficos del panel",
    "settings": "Ajustes (concurrencia, escaneo automático)",
}


class BackupError(Exception):
    pass


def encrypt(data, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    raw = gzip.compress(json.dumps(data, ensure_ascii=False).encode())
    key = derive(password, salt, CURRENT_LOG_N)
    return MAGIC + bytes([CURRENT_LOG_N]) + salt + nonce + AESGCM(key).encrypt(nonce, raw, None)


def decrypt(blob, password):
    if blob.startswith(MAGIC) and len(blob) > 41:
        log_n, rest = blob[4], blob[5:]
        if not 14 <= log_n <= 20:
            raise BackupError("Formato de exportación desconocido")
    elif blob.startswith(MAGIC_V1) and len(blob) > 40:
        log_n, rest = LEGACY_LOG_N, blob[4:]
    else:
        raise BackupError("El fichero no es una exportación de Linux Command Center (.lcc)")
    salt, nonce, ct = rest[:16], rest[16:28], rest[28:]
    try:
        raw = AESGCM(derive(password, salt, log_n)).decrypt(nonce, ct, None)
    except Exception:
        raise BackupError("Contraseña del fichero incorrecta (o fichero dañado)")
    data = json.loads(gzip.decompress(raw))
    if data.get("format") != FORMAT:
        raise BackupError("Formato de exportación desconocido")
    return data
