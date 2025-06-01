from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

class AESCipher:
    def __init__(self, password: str):
        self.salt = os.urandom(16)
        self.key = self.derive_key(password)

    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, data: bytes) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        # Store salt + iv + encrypted data as base64
        return base64.b64encode(self.salt + iv + encrypted_data).decode('utf-8')

    def decrypt(self, encrypted_data: str, password: str) -> bytes:
        encrypted_data = base64.b64decode(encrypted_data)
        self.salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_text = encrypted_data[32:]
        self.key = self.derive_key(password)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_text) + decryptor.finalize()
