from dataclasses import dataclass
from typing import List, Any
import hashlib
import json

class Block:
    def __init__(self, index, previous_hash, transactions, timestamp):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        tx_dicts = [tx.to_dict() for tx in self.transactions]
        data = json.dumps(tx_dicts, sort_keys=True) + str(self.timestamp) + (self.previous_hash or '')
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'timestamp': self.timestamp,
            'hash': self.hash,
        }