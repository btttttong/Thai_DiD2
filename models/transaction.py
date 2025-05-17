from ipv8.keyvault.crypto import default_eccrypto
from cryptography.exceptions import InvalidSignature
import time
from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.messaging.serialization import default_serializer

@dataclass
class Transaction(DataClassPayload[1]):
    sender_mid: bytes
    receiver_mid: bytes
    cert_hash: bytes
    timestamp: float
    signature: bytes
    public_key: bytes

    @classmethod
    def serializer(cls):
        return default_serializer(cls, [
            (bytes, "sender_mid"),
            (bytes, "receiver_mid"),
            (bytes, "cert_hash"),
            (float, "timestamp"),
            (bytes, "signature"),
            (bytes, "public_key"),
        ])
    
    def to_dict(self):
        return {
            'sender_mid': self.sender_mid.hex(),  #convert bytes to hex string
            'receiver_mid': self.receiver_mid.hex(),
            'cert_hash': self.cert_hash.hex(),
            'timestamp': self.timestamp,
            'signature': self.signature.hex(),
            'public_key': self.public_key.hex(),
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            sender_mid=bytes.fromhex(d["sender_mid"]),
            receiver_mid=bytes.fromhex(d["receiver_mid"]),
            cert_hash=bytes.fromhex(d["cert_hash"]),
            timestamp=d["timestamp"],
            signature=bytes.fromhex(d["signature"]) if d["signature"] else None,
            public_key=bytes.fromhex(d["public_key"]) if d["public_key"] else None
        )


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
