"""Credential encryption with a master password.

The key is derived with scrypt and only lives in memory while the application
is unlocked. The database only holds encrypted data (AES-GCM).

Derivation is slow on purpose (it slows down brute-force attacks): it is computed outside the
main loop (derive_for / derive) and the database writes are done afterwards.
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import db

CHECK_PLAINTEXT = b"inventario-vm-ok"
SECRET_COLUMNS = ("password_enc", "private_key_enc", "key_passphrase_enc", "sudo_password_enc")
LEGACY_LOG_N = 15   # old installations: scrypt N=2^15 (32 MB)
CURRENT_LOG_N = 17  # current: scrypt N=2^17 (128 MB, ~0.5 s), OWASP recommendation


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
        """Candidate key using the saved parameters (slow: call with asyncio.to_thread)."""
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
        """Re-encrypts everything with a new key (password change or parameter upgrade)."""
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
        """Synchronous version (tests and scripts). The web app uses derive in a thread + rekey."""
        if not self.unlock(old):
            return False
        salt = os.urandom(16)
        self.rekey(derive(new, salt), salt)
        return True

    def audit_key(self):
        """Random key used to sign the audit log, stored encrypted. None if locked.

        It is independent of the master password, so changing it does not invalidate old signatures.
        """
        if not self.key:
            return None
        blob = db.get_setting("audit_key_enc")
        if not blob:
            db.set_setting("audit_key_enc", _enc(self.key, os.urandom(32).hex().encode()))
            blob = db.get_setting("audit_key_enc")
        return bytes.fromhex(_dec(self.key, blob).decode())


vault = Vault()
