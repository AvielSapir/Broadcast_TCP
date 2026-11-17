import os
import hashlib
import hmac

class CryptoEngine:
    def __init__(self, key: bytes):
        if isinstance(key, str):
            key = key.encode("utf-8")
        self.enc_key = hashlib.sha256(key + b":enc").digest()
        self.mac_key = hashlib.sha256(key + b":mac").digest()

    def _keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = hashlib.sha256(key + nonce + counter.to_bytes(4, byteorder="big")).digest()
            stream.extend(block)
            counter += 1
        return bytes(stream[:length])

    def encrypt(self, plaintext: bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = os.urandom(16)
        stream = self._keystream(self.enc_key, nonce, len(plaintext))
        ciphertext = bytes([p ^ s for p, s in zip(plaintext, stream)])
        tag = hmac.new(self.mac_key, nonce + ciphertext, hashlib.sha256).digest()
        return nonce + tag + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        if len(data) < 48:
            raise ValueError("Payload too short for decryption")
        nonce = data[:16]
        tag = data[16:48]
        ciphertext = data[48:]
        expected_tag = hmac.new(self.mac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication tag mismatch")
        stream = self._keystream(self.enc_key, nonce, len(ciphertext))
        return bytes([c ^ s for c, s in zip(ciphertext, stream)])
