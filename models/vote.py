from dataclasses import dataclass
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.messaging.serialization import default_serializer

@dataclass
class Vote(DataClassPayload[2]):
    block_hash: bytes
    voter_mid: bytes
    vote_decision: bytes  # e.g., b"accept" or b"reject"
    timestamp: float
    signature: bytes
    public_key: bytes

    @classmethod
    def serializer(cls):
        return default_serializer(cls, [
            (bytes, "block_hash"),
            (bytes, "voter_mid"),
            (bytes, "vote_decision"),
            (float, "timestamp"),
            (bytes, "signature"),
            (bytes, "public_key")
        ])
