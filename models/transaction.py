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