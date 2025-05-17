from dataclasses import dataclass
from typing import List
from ipv8.messaging.payload_dataclass import DataClassPayload

@dataclass
class BlockPayload(DataClassPayload[4]):
    index: int
    previous_hash: bytes
    transactions: bytes
    signature: bytes
    public_key: bytes
    db_id: bytes
