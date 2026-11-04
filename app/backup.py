"""Portable full export (.lcc): compressed JSON encrypted with a password chosen at export time."""
import gzip
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vault import CURRENT_LOG_N, LEGACY_LOG_N, derive

# LCC1: scrypt N=2^15 (old versions, read-only). LCC2: one byte with log2(N) after the marker.
MAGIC = b"LCC2"
MAGIC_V1 = b"LCC1"
FORMAT = "linux-command-center-export"

SECTIONS = {
    "vms": "Servers (with their own user/password and tags)",
    "credentials": "Shared credentials",
    "organization": "Clients, environments and tags",
    "commands": "Saved commands",
    "charts": "Dashboard charts",
    "settings": "Settings (concurrency, automatic scan)",
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
            raise BackupError("Unknown export format")
    elif blob.startswith(MAGIC_V1) and len(blob) > 40:
        log_n, rest = LEGACY_LOG_N, blob[4:]
    else:
        raise BackupError("The file is not a Linux Command Center export (.lcc)")
    salt, nonce, ct = rest[:16], rest[16:28], rest[28:]
    try:
        raw = AESGCM(derive(password, salt, log_n)).decrypt(nonce, ct, None)
    except Exception:
        raise BackupError("Wrong file password (or damaged file)")
    data = json.loads(gzip.decompress(raw))
    if data.get("format") != FORMAT:
        raise BackupError("Unknown export format")
    return data
