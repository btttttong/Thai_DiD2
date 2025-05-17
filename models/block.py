from dataclasses import dataclass
from typing import List, Any
import hashlib
import json

class Block:
    msg_id = 3

    def __init__(self, index, previous_hash, transactions, signature=None, public_key=None):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.signature = signature  # bytes
        self.public_key = public_key  # bytes
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        tx_dicts = [tx.to_dict() for tx in self.transactions]
        data = json.dumps(tx_dicts, sort_keys=True) + (self.previous_hash or '')
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'hash': self.hash,
        }
    
    def get_bytes(self):
        block_dict = self.to_dict()
        # ลบ signature และ public_key ออกจากข้อมูลที่จะเซ็น
        block_dict.pop('signature', None)
        block_dict.pop('public_key', None)
        block_json = json.dumps(block_dict, sort_keys=True)
        return block_json.encode('utf-8')