"""Cifrado de credenciales con una contraseña maestra.

La clave se deriva con scrypt y solo vive en memoria mientras la aplicación
está desbloqueada. En la base de datos únicamente hay datos cifrados (AES-GCM).

La derivación es lenta a propósito (frena ataques de fuerza bruta): se calcula fuera del
bucle principal (derive_for / derive) y las escrituras en la base de datos se hacen después.
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import db

CHECK_PLAINTEXT = b"inventario-vm-ok"
SECRET_COLUMNS = ("password_enc", "private_key_enc", "key_passphrase_enc", "sudo_password_enc")
LEGACY_LOG_N = 15   # instalaciones antiguas: scrypt N=2^15 (32 MB)
CURRENT_LOG_N = 17  # actual: scrypt N=2^17 (128 MB, ~0,5 s), recomendación OWASP


def derive(password, salt, log_n=CURRENT_LOG_N):
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** log_n, r=8, p=1,
                          maxmem=256 * 1024 * 1024, dklen=32)


def _enc(key, text):
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(key).encrypt(nonce, text, None)).decode()


def _dec(key, blob):
    raw = base64.b64decode(blob)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None)


class Vault:
    def __init__(self):
        self.key = None

    @property
    def initialized(self):
        return db.get_setting("vault_salt") is not None

    @property
    def unlocked(self):
        return self.key is not None

    @property
    def log_n(self):
        return int(db.get_setting("vault_kdf_log_n", LEGACY_LOG_N))

    def needs_upgrade(self):
        return self.log_n < CURRENT_LOG_N

    def setup(self, password):
        salt = os.urandom(16)
        self.setup_with_key(derive(password, salt), salt)

    def setup_with_key(self, key, salt):
        db.set_setting("vault_salt", salt.hex())
        db.set_setting("vault_kdf_log_n", CURRENT_LOG_N)
        db.set_setting("vault_check", _enc(key, CHECK_PLAINTEXT))
        self.key = key

    def derive_for(self, password):
        """Clave candidata con los parámetros guardados (lento: llamar con asyncio.to_thread)."""
        return derive(password, bytes.fromhex(db.get_setting("vault_salt")), self.log_n)

    def check_key(self, key):
        try:
            return _dec(key, db.get_setting("vault_check")) == CHECK_PLAINTEXT
        except Exception:
            return False

    def unlock_with_key(self, key):
        if not self.check_key(key):
            return False
        self.key = key
        return True

    def unlock(self, password):
        return self.unlock_with_key(self.derive_for(password))

    def lock(self):
        self.key = None

    def encrypt(self, text):
        if text is None or text == "":
            return None
        return _enc(self.key, text.encode())

    def decrypt(self, blob):
        if not blob:
            return None
        return _dec(self.key, blob).decode()

    def rekey(self, new_key, salt, log_n=CURRENT_LOG_N):
        """Vuelve a cifrar todo con una clave nueva (cambio de contraseña o mejora de parámetros)."""
        old_key = self.key
        with db.tx() as c:
            for row in c.execute("SELECT * FROM credentials").fetchall():
                values = [_enc(new_key, _dec(old_key, row[col])) if row[col] else None for col in SECRET_COLUMNS]
                c.execute(f"UPDATE credentials SET {', '.join(f'{col}=?' for col in SECRET_COLUMNS)} "
                          "WHERE id=?", (*values, row["id"]))
            updates = [("vault_salt", salt.hex()), ("vault_check", _enc(new_key, CHECK_PLAINTEXT)),
                       ("vault_kdf_log_n", str(log_n))]
            audit_blob = c.execute("SELECT value FROM settings WHERE key='audit_key_enc'").fetchone()
            if audit_blob:
                updates.append(("audit_key_enc", _enc(new_key, _dec(old_key, audit_blob["value"]))))
            for key, value in updates:
                c.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.key = new_key

    def change_password(self, old, new):
        """Versión síncrona (tests y scripts). La web usa derive en un hilo + rekey."""
        if not self.unlock(old):
            return False
        salt = os.urandom(16)
        self.rekey(derive(new, salt), salt)
        return True

    def audit_key(self):
        """Clave aleatoria para firmar la auditoría, guardada cifrada. None si está bloqueado.

        Es independiente de la contraseña maestra, así cambiarla no invalida las firmas antiguas.
        """
        if not self.key:
            return None
        blob = db.get_setting("audit_key_enc")
        if not blob:
            db.set_setting("audit_key_enc", _enc(self.key, os.urandom(32).hex().encode()))
            blob = db.get_setting("audit_key_enc")
        return bytes.fromhex(_dec(self.key, blob).decode())


vault = Vault()
