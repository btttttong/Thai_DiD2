from ipv8.keyvault.crypto import default_eccrypto
from cryptography.exceptions import InvalidSignature
import time

class Transaction:
    msg_id = 1
    def __init__(self, sender_mid, receiver_mid, cert_hash, timestamp=None,
                 signature=None, public_key=None):
        self.sender_mid = sender_mid
        self.receiver_mid = receiver_mid
        self.cert_hash = cert_hash
        self.timestamp = timestamp or int(time.time())
        self.signature = signature
        self.public_key = public_key

    def to_dict(self):
        return {
            "sender_mid": self.sender_mid.hex(),
            "receiver_mid": self.receiver_mid.hex(),
            "cert_hash": self.cert_hash.hex(),
            "timestamp": self.timestamp,
            "signature": self.signature.hex() if self.signature else None,
            "public_key": self.public_key.hex() if self.public_key else None,
        }

    def get_bytes(self):
        # Prepare bytes for signing/verification (exclude signature & public_key)
        d = self.to_dict()
        d.pop("signature", None)
        d.pop("public_key", None)
        import json
        return json.dumps(d, sort_keys=True).encode("utf-8")

    def sign(self, private_key):
        message = self.get_bytes()
        self.signature = default_eccrypto.create_signature(private_key, message)
        self.public_key = default_eccrypto.key_to_bin(private_key.pub())

    def is_valid(self):
        if not self.signature or not self.public_key:
            return False
        try:
            pk = default_eccrypto.key_from_public_bin(self.public_key)
            pk.verify(self.signature, self.get_bytes())
            return True
        except InvalidSignature:
            return False
