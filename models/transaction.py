from ipv8.messaging.payload import Payload
from ipv8.keyvault.crypto import default_eccrypto
from cryptography.exceptions import InvalidSignature
from ipv8.messaging.serialization import default_serializers
import json

class Transaction(Payload):
    msg_id = 1

    def __init__(self, sender_mid=b"", receiver_mid="", cert_hash=b"", timestamp=0.0,
                 signature=b"", public_key=b"", db_id=""):
        super().__init__()
        self.sender_mid = sender_mid
        self.receiver_mid = receiver_mid
        self.cert_hash = cert_hash
        self.timestamp = timestamp
        self.signature = signature
        self.public_key = public_key
        self.db_id = db_id

    def to_dict(self):
        return {
            "sender_mid": self.sender_mid.hex(),
            "receiver_mid": self.receiver_mid,
            "cert_hash": self.cert_hash.hex(),
            "timestamp": self.timestamp,
            "signature": self.signature.hex() if self.signature else None,
            "public_key": self.public_key.hex() if self.public_key else None,
            "db_id": self.db_id
        }

    def get_bytes(self):
        d = self.to_dict()
        d.pop("signature", None)
        d.pop("public_key", None)
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

    def to_pack_list(self):
        return [
            (default_serializers.serializable_bytes, self.sender_mid),
            (default_serializers.serializable_bytes, self.receiver_mid.encode("utf-8")),
            (default_serializers.serializable_bytes, self.cert_hash),
            (default_serializers.double, self.timestamp),
            (default_serializers.serializable_bytes, self.signature),
            (default_serializers.serializable_bytes, self.public_key),
            (default_serializers.serializable_bytes, self.db_id.encode("utf-8")),
        ]

    @classmethod
    def get_format(cls):
        return [
            default_serializers.serializable_bytes,
            default_serializers.serializable_bytes,
            default_serializers.serializable_bytes,
            default_serializers.double,
            default_serializers.serializable_bytes,
            default_serializers.serializable_bytes,
            default_serializers.serializable_bytes
        ]

    @classmethod
    def from_unpack_list(cls, *pack):
        return cls(
            sender_mid=pack[0],
            receiver_mid=pack[1].decode("utf-8"),
            cert_hash=pack[2],
            timestamp=pack[3],
            signature=pack[4],
            public_key=pack[5],
            db_id=pack[6].decode("utf-8"),
        )