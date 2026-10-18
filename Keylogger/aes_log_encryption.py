"""
AES Log Encryption Vault
========================
Provides authenticated symmetric encryption (AES-CBC + HMAC-SHA256)
for protecting raw keystroke and audit logs at rest.

Discussion Reference: https://github.com/haroonatieeq352/key_loger_python_project/discussions/3
Co-developed by: Haroon Atieeq & Ahsan Tariq (@ahsantariq07248988)
"""

import os
from typing import List, Optional
from cryptography.fernet import Fernet, InvalidToken


class EncryptedLogVault:
    """
    Encrypts log entries in memory before persisting them to disk.
    Guarantees tamper-detection and zero plaintext exposure at rest.
    """

    def __init__(self, encryption_key: Optional[bytes] = None):
        """
        Initializes the cipher with a provided 256-bit Fernet key or
        fetches it from the environment variable 'KEYLOGGER_VAULT_KEY'.
        """
        if encryption_key:
            self._key = encryption_key
        else:
            env_key = os.getenv("KEYLOGGER_VAULT_KEY")
            if env_key:
                self._key = env_key.encode("utf-8")
            else:
                self._key = Fernet.generate_key()

        self._cipher = Fernet(self._key)

    @property
    def key(self) -> bytes:
        """Returns the active symmetric encryption key."""
        return self._key

    def append_log(self, file_path: str, raw_entry: str) -> bool:
        """
        Encrypts the plaintext entry and appends the ciphertext block to disk.
        """
        try:
            ciphertext = self._cipher.encrypt(raw_entry.encode("utf-8"))
            with open(file_path, "ab") as f:
                f.write(ciphertext + b"\n")
            return True
        except Exception as e:
            print(f"[!] Error encrypting log entry: {e}")
            return False

    def read_logs(self, file_path: str) -> List[str]:
        """
        Reads and decrypts all ciphertext blocks from the specified log file.
        Raises a warning if any block has been tampered with or corrupted.
        """
        if not os.path.exists(file_path):
            return []

        decrypted_entries: List[str] = []
        with open(file_path, "rb") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    plaintext = self._cipher.decrypt(clean_line).decode("utf-8")
                    decrypted_entries.append(plaintext)
                except InvalidToken:
                    print(f"[!] Integrity verification failed on line {line_no}: Tampering detected.")
                except Exception as e:
                    print(f"[!] Error decrypting line {line_no}: {e}")

        return decrypted_entries
