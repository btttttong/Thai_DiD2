import hashlib
from models.block import Block
from models.transaction import Transaction
from ipv8.keyvault.crypto import default_eccrypto
import time

class Blockchain:
    def __init__(self, max_block_size=5, validators=None):
        self.chain = []
        self.pending_transactions = []
        self.proposed_blocks = {}  # เก็บบล็อกชั่วคราวที่รับมา
        self.max_block_size = max_block_size
        self.validators = validators if validators else []

    def add_pending_transaction(self, tx: Transaction):
        # TODO: เพิ่ม validation tx เบื้องต้นได้
        self.pending_transactions.append(tx)

    def propose_block(self, private_key=None):
        if len(self.pending_transactions) == 0:
            return None

        # สร้างบล็อกใหม่จาก pending tx สูงสุด max_block_size
        txs = self.pending_transactions[:self.max_block_size]
        index = len(self.chain)
        previous_hash = self.chain[-1].hash if self.chain else None
        timestamp = int(time.time())
        block = Block(index, previous_hash, txs, timestamp)

        # เซ็นบล็อก ถ้ามี private_key (key ของ proposer)
        if private_key:
            block_bytes = block.get_bytes()
            signature = default_eccrypto.create_signature(private_key, block_bytes)
            block.signature = signature
            block.public_key = default_eccrypto.key_to_bin(private_key.pub())

        return block

    def validate_block(self, block: Block):
        # ตรวจสอบ hash
        if block.hash != block.calculate_hash():
            return False

        # ตรวจสอบ previous_hash เชื่อมกับ chain
        if block.index > 0:
            if not self.chain or self.chain[-1].hash != block.previous_hash:
                return False

        # ตรวจสอบ signature บล็อก
        if not default_eccrypto.verify_signature(
            block.public_key,
            block.signature,
            block.get_bytes()
        ):
            return False

        # ตรวจสอบ transaction ทุกตัว (สมมติ Transaction มี validate method)
        for tx in block.transactions:
            if not tx.is_valid():
                return False

        return True

    def store_proposed_block(self, block: Block):
        self.proposed_blocks[block.hash] = block

    def get_proposed_block(self, block_hash):
        return self.proposed_blocks.get(block_hash)

    def finalize_block(self, block_hash, validator):
        block = self.get_proposed_block(block_hash)
        if not block:
            return False

        # เพิ่มบล็อกลง chain
        self.chain.append(block)

        # ลบ tx ในบล็อกจาก pending_transactions
        tx_hashes = set(tx.cert_hash for tx in block.transactions)
        self.pending_transactions = [tx for tx in self.pending_transactions if tx.cert_hash not in tx_hashes]

        # ลบบล็อกที่ finalize ออกจาก proposed_blocks
        self.proposed_blocks.pop(block_hash, None)
        return True
