from ipv8.keyvault.crypto import default_eccrypto

class Transaction:
    def __init__(self, sender_mid, receiver_mid, cert_hash, signature, public_key, db_id):
        self.sender_mid = sender_mid  # str
        self.receiver_mid = receiver_mid  # str
        self.cert_hash = cert_hash  # str
        self.signature = signature  # hex str
        self.public_key = public_key  # hex str
        self.db_id = db_id  # str

    def to_dict(self):
        return {
            "sender_mid": self.sender_mid,
            "receiver_mid": self.receiver_mid,
            "cert_hash": self.cert_hash,
            "signature": self.signature,
            "public_key": self.public_key,
            "db_id": self.db_id
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["sender_mid"],
            data["receiver_mid"],
            data["cert_hash"],
            data["signature"],
            data["public_key"],
            data["db_id"]
        )

    def get_bytes(self):
        return (self.sender_mid + self.receiver_mid + self.cert_hash + self.db_id).encode()

    def sign(self, private_key):
        self.signature = default_eccrypto.create_signature(private_key, self.get_bytes()).hex()
        self.public_key = default_eccrypto.key_to_bin(private_key.pub()).hex()
