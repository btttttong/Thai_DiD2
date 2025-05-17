from ipv8.messaging.payload import Payload
from ipv8.messaging.serialization import default_serializer

class Vote(Payload):
    msg_id = 2

    def __init__(self, block_hash=b"", voter_mid=b"", vote_decision=b"", timestamp=0.0, signature=b"", public_key=b""):
        super().__init__()
        self.block_hash = block_hash
        self.voter_mid = voter_mid
        self.vote_decision = vote_decision
        self.timestamp = timestamp
        self.signature = signature
        self.public_key = public_key

    def to_pack_list(self):
        pack = [
            self.sender_mid.hex().encode("utf-8"),
            self.receiver_mid.hex().encode("utf-8"),
            self.cert_hash.hex().encode("utf-8"),
            str(self.timestamp).encode("utf-8"),
            self.signature.hex().encode("utf-8"),
            self.public_key.hex().encode("utf-8"),
            self.db_id.encode("utf-8")
        ]
        print("Packing Transaction:", pack)
        return pack

    @classmethod
    def from_unpack_list(cls, pack):
        return cls(
            block_hash=bytes.fromhex(pack[0].decode("utf-8")),
            voter_mid=bytes.fromhex(pack[1].decode("utf-8")),
            vote_decision=pack[2],
            timestamp=float(pack[3].decode("utf-8")),
            signature=bytes.fromhex(pack[4].decode("utf-8")),
            public_key=bytes.fromhex(pack[5].decode("utf-8"))
        )

    @classmethod
    def get_format(cls):
        return [
            default_serializer.get_serializer(bytes),  # block_hash (encoded)
            default_serializer.get_serializer(bytes),  # voter_mid (encoded)
            default_serializer.get_serializer(bytes),  # vote_decision
            default_serializer.get_serializer(bytes),  # timestamp (encoded string)
            default_serializer.get_serializer(bytes),  # signature (encoded)
            default_serializer.get_serializer(bytes)   # public_key (encoded)
        ]