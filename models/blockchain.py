from .block import Block
from time import time

class Blockchain:
    def __init__(self, max_block_size, validators: list):
        self.chain = []
        self.max_block_size = max_block_size
        self.validators = validators  # Authorized validators
        self.pending_transactions = []
        self.proposed_blocks = {}  # Store proposed blocks by block_hash
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", [], time())
        self.chain.append(genesis_block)

    def add_pending_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def propose_block(self):
        """Build a block proposal if there are pending transactions."""
        if len(self.pending_transactions) == 0:
            print("No transactions to propose.")
            return None

        previous_block = self.chain[-1]
        block = Block(
            index=previous_block.index + 1,
            previous_hash=previous_block.hash,
            transactions=self.pending_transactions.copy(),
            timestamp=time()
        )
        self.proposed_blocks[block.hash] = block
        return block

    def get_proposed_block(self, block_hash: str):
        """Retrieve a proposed block by its hash."""
        return self.proposed_blocks.get(block_hash, None)

    def finalize_block(self, block_hash: str, validator: str):
        """Finalize a block after it has received enough votes."""
        if validator not in self.validators:
            print(f"Validator {validator} is not authorized to finalize blocks.")
            return None

        block = self.get_proposed_block(block_hash)
        if not block:
            print(f"Block with hash {block_hash} not found in proposed blocks.")
            return None

        if not self.is_valid_block(block):
            print(f"Block {block_hash} is invalid.")
            return None

        self.chain.append(block)
        print(f"Block {block_hash} finalized and added by {validator}.")
        # Remove transactions from pending pool
        self.pending_transactions = [
            tx for tx in self.pending_transactions if tx not in block.transactions
        ]
        # Cleanup proposed blocks
        del self.proposed_blocks[block_hash]
        return block

    def is_valid_block(self, block: Block) -> bool:
        """Validate that block links to the last block in the chain."""
        if block.previous_hash != self.chain[-1].hash:
            print("Invalid previous block hash.")
            return False
        return True

    def get_last_block(self):
        return self.chain[-1]

    def to_dict(self):
        """Return the whole chain as a list of dictionaries."""
        return [block.to_dict() for block in self.chain]