import os, json, asyncio, hashlib
from random import choice
from time import time
from threading import Thread
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.types import Peer
from ipv8_service import IPv8
from ipv8.keyvault.crypto import default_eccrypto, ECCrypto
from cryptography.exceptions import InvalidSignature
import asyncio
from models.transaction import Transaction
from models.blockchain import Blockchain
from models.vote import Vote
from models.block import Block

blockchain_community = None  # globally accessible
from models.blockpayload import BlockPayload

from web_controller import NodeWeb


def verify_signature(signature: bytes, public_key: bytes, message: bytes) -> bool:
    try:
        pk = default_eccrypto.key_from_public_bin(public_key)
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False

# def block_to_payload(block: Block) -> BlockPayload:
#     if block.previous_hash is None:
#         raise ValueError("Block missing previous_hash")
#     if block.transactions is None:
#         raise ValueError("Block missing transactions")
#     if block.signature is None:
#         raise ValueError("Block missing signature")
#     if block.public_key is None:
#         raise ValueError("Block missing public_key")

#     tx_jsons = []
#     for tx in block.transactions:
#         if tx is None:
#             raise ValueError("Block contains None transaction")
#         tx_json = json.dumps(tx.to_dict(), sort_keys=True).encode('utf-8')
#         tx_jsons.append(tx_json)

#     previous_hash_bytes = (block.previous_hash.encode('utf-8')
#                            if isinstance(block.previous_hash, str)
#                            else block.previous_hash)

#     return BlockPayload(
#         index=block.index,
#         previous_hash=previous_hash_bytes,
#         transactions=tx_jsons,
#         timestamp=block.timestamp,
#         signature=block.signature,
#         public_key=block.public_key
#     )

def block_to_payload(block: Block) -> BlockPayload:
    tx_jsons = [tx.to_dict() for tx in block.transactions]
    tx_bytes = json.dumps(tx_jsons).encode('utf-8')  # Serialize as one field

    return BlockPayload(
        index=block.index,
        previous_hash=block.previous_hash.encode('utf-8') if isinstance(block.previous_hash, str) else block.previous_hash,
        transactions=tx_bytes,  # Single JSON-encoded bytes
        timestamp=block.timestamp,
        signature=block.signature,
        public_key=block.public_key
    )


# def payload_to_block(payload: BlockPayload) -> Block:
#     tx_list = [json.loads(tx_bytes.decode('utf-8')) for tx_bytes in payload.transactions]
#     # You will have to reconstruct Transaction objects from dicts if needed
#     # Here we pass empty list for demonstration
#     return Block(
#         index=payload.index,
#         previous_hash=payload.previous_hash.decode('utf-8'),
#         transactions=[],  # Replace with real deserialization logic if needed
#         timestamp=payload.timestamp,
#         signature=payload.signature,
#         public_key=payload.public_key
#     )

def payload_to_block(payload: BlockPayload) -> Block:
    tx_dicts = json.loads(payload.transactions.decode('utf-8'))
    tx_list = [Transaction.from_dict(d) for d in tx_dicts]

    return Block(
        index=payload.index,
        previous_hash=payload.previous_hash.decode('utf-8'),
        transactions=tx_list,
        timestamp=payload.timestamp,
        signature=payload.signature,
        public_key=payload.public_key
    )



class BlockchainCommunity(Community, PeerObserver):
    community_id = b"myblockchain-test-01"

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        global blockchain_community
        blockchain_community = self
        self.started_callback = lambda: print("✅ blockchain_community is ready!")
        self.my_key = default_eccrypto.key_from_private_bin(self.my_peer.key.key_to_bin())
        self.known_peers = set()
        self.seen_message_hashes = set()
        self.vote_collections = {}
        self.node_id = None
        self.current_proposed_block = None

        # self.serializer.add_serializable(Transaction)
        # self.serializer.add_serializable(Vote)
        # self.serializer.add_serializable(Block)

        # self.serializer.add_serializable(Transaction)

        # Load role config
        self.role = self.load_node_role()
        self.validators = self.load_validators()
        self.blockchain = Blockchain(max_block_size=5, validators=self.validators)

    def load_node_role(self):
        config_file = "node_config.json"
        if os.path.exists(config_file):
            with open(config_file) as f:
                config = json.load(f)
                print(f"[{self.my_peer.mid.hex()}] Assigned role: {config.get(self.my_peer.mid.hex(), {}).get('role', 'unknown')}")
                return config.get(self.my_peer.mid.hex(), {}).get("role", "unknown")
        return "unknown"
    
    def load_validators(self):
        config_file = "node_config.json"
        if os.path.exists(config_file):
            with open(config_file) as f:
                config = json.load(f)
                return [bytes.fromhex(k) for k, v in config.items() if v.get("role") == "validator"]
        return []

    def is_my_turn(self):
        validators = sorted(self.blockchain.validators)
        block_height = self.blockchain.height
        current_index = block_height % len(validators)
        return self.my_peer.mid == validators[current_index]

    def broadcast(self, payload, exclude_peer=None):
        for peer in self.get_peers():
            if peer != exclude_peer and peer != self.my_peer:
                self.ez_send(peer, payload)

    def on_peer_added(self, peer: Peer):
        self.known_peers.add(peer.mid)
        print(f"[{self.my_peer.mid.hex()}] connected to {peer.mid.hex()}")

    def on_peer_removed(self, peer: Peer):
        self.known_peers.discard(peer.mid)
        print(f"[{self.my_peer.mid.hex()}] disconnected from {peer.mid.hex()}")

    def started(self):
        global blockchain_community
        blockchain_community = self
        self.node_id = self.my_peer.mid.hex()[:6]
        self.network.add_peer_observer(self)
        self.add_message_handler(Transaction, self.on_transaction_received)
        self.add_message_handler(Vote, self.on_vote_received)
        self.add_message_handler(BlockPayload, self.on_block_payload_received)

        if self.role == "sender":
            # send dummy transaction since ipv8 is somehow not recoginze the first tx
            # this will be raised some error but it will be ignored
            self.create_and_broadcast_transaction(
                recipient_id="stu123",
                issuer_id="uniABC",
                cert_hash=hashlib.sha256(b"stu123:uniABC:db001:" + str(time()).encode()).hexdigest(),
                db_id="db001"
            )
            print(f"[{self.node_id}] Dummy transaction broadcasted: {hashlib.sha256(b'stu123:uniABC:db001:' + str(time()).encode()).hexdigest()[:8]}")

            print(f"[{self.node_id}] Starting transaction sender...")
            self.register_task("send_transaction", send_transaction, interval=5, delay=2)

    def log_peers(self):
        print(f"[{self.node_id}] Known peers: {len(self.known_peers)} | Connected peers: {len(self.get_peers())}")

    @lazy_wrapper(Transaction)
    def on_transaction_received(self, peer: Peer, tx: Transaction):
        message_id = hashlib.sha256(tx.cert_hash + str(tx.timestamp).encode()).hexdigest()
        if message_id in self.seen_message_hashes:
            return

        self.seen_message_hashes.add(message_id)
        if not verify_signature(tx.signature, tx.public_key,
                                tx.sender_mid + tx.receiver_mid + tx.cert_hash + str(tx.timestamp).encode()):
            print(f"[{self.node_id}] Invalid TX from {peer.mid.hex()}")
            return

        self.blockchain.add_pending_transaction(tx)
        print(f"[{self.node_id}] TX received from {tx.sender_mid.hex()[:6]} to {tx.receiver_mid.hex()[:6]} pending transactions: {len(self.blockchain.pending_transactions)}")
        self.broadcast(tx)

        if len(self.blockchain.pending_transactions) >= self.blockchain.max_block_size:
            print(f"[{self.node_id}] Block size reached, proposing block...")
            self.propose_block()

    def broadcast_block(self, block: Block):
        block_payload = block_to_payload(block)
        for peer in self.get_peers():
            if peer != self.my_peer:
                self.ez_send(peer, block_payload)
        print(f"[{self.node_id}] Block broadcasted: {block.hash[:8]}")


    def propose_block(self):
        if self.role != "validator" or not self.is_my_turn():
            return
        if self.current_proposed_block is not None:
            return

        block = self.blockchain.propose_block(private_key=self.my_key)
        # print(f"[{self.node_id}] Proposed Block: {block.hash}")
        if block:
            self.current_proposed_block = block
            print(f"[{self.node_id}] Proposing Block {block.hash[:8]}")
            self.broadcast_block(block)  # Broadcast block แทน vote ก่อน
            # Proposer ก็ vote ตัวเองด้วย

            # ignore this for now

            # vote = self.create_vote(block.hash, 'accept')
            # self.broadcast(vote)

    def broadcast_finalized_block(self, block: Block):
        block_payload = block_to_payload(block)
        for peer in self.get_peers():
            if peer != self.my_peer:
                self.ez_send(peer, block_payload)
        print(f"[{self.node_id}] Finalized block broadcasted: {block.hash.hex()[:8]}")

    @lazy_wrapper(BlockPayload)
    def on_block_payload_received(self, peer: Peer, block_payload: BlockPayload):
        block = payload_to_block(block_payload)

        if block.hash.startswith("dummy"):  # You can choose any unique marker
            print(f"[{self.node_id}] Received DUMMY block from {peer.mid.hex()[:6]}")
            return

        if block.hash in self.seen_message_hashes:
            return

        print(f"[{self.node_id}] Received block from {peer.mid.hex()[:6]}: {block.hash[:8]}")

        self.seen_message_hashes.add(block.hash)

        # ตรวจสอบ signature บล็อก
        if not verify_signature(block.signature, block.public_key, block.get_bytes()):
            print(f"[{self.node_id}] Invalid block signature from {peer.mid.hex()[:6]}")
            return

        # ตรวจสอบความถูกต้องของบล็อก (เช่น tx ถูกต้อง, เชื่อมโยงบล็อกก่อนหน้า)
        if not self.blockchain.validate_block(block):
            print(f"[{self.node_id}] Invalid block content from {peer.mid.hex()[:6]}")
            return

        # เก็บบล็อกชั่วคราว (ถ้ามี)
        self.blockchain.store_proposed_block(block)

        # สร้าง vote accept และเซ็น

        # ignore this for now

        # vote = self.create_vote(block.hash, 'accept')
        # self.broadcast(vote)
        # print(f"[{self.node_id}] Vote sent for block {block_hash_hex[:8]}")
    
    @lazy_wrapper(Vote)
    def on_vote_received(self, peer: Peer, vote: Vote):
        block_hash_str = vote.block_hash.hex()
        print(f"[{self.node_id}] Received vote from {vote.voter_mid.hex()[:6]} on block {block_hash_str[:8]} with decision {vote.vote_decision.decode()}")

        if block_hash_str not in self.vote_collections:
            self.vote_collections[block_hash_str] = []

        if not verify_signature(
            vote.signature,
            vote.public_key,
            vote.block_hash + vote.voter_mid + vote.vote_decision + str(vote.timestamp).encode()
        ):
            print(f"[{self.node_id}] Invalid vote signature from {vote.voter_mid.hex()[:6]}")
            return

        if vote.voter_mid not in [v.voter_mid for v in self.vote_collections[block_hash_str]]:
            self.vote_collections[block_hash_str].append(vote)

        accept_votes = sum(1 for v in self.vote_collections[block_hash_str] if v.vote_decision == b'accept')
        print(f"[{self.node_id}] Total accept votes for block {block_hash_str[:8]}: {accept_votes}")

        if accept_votes >= 3:
            print(f"[{self.node_id}] Vote threshold reached for block {block_hash_str[:8]}")
            self.finalize_block(block_hash_str)

    def finalize_block(self, block_hash_hex: str):
        block = self.blockchain.get_proposed_block(block_hash_hex)
        if block:
            success = self.blockchain.finalize_block(block_hash_hex, validator=self.my_peer.mid.hex())
            if success:
                self.current_proposed_block = None
                print(f"[{self.node_id}] Block {block_hash_hex[:8]} finalized and added to chain!")
                self.broadcast_finalized_block(block)
            else:
                print(f"[{self.node_id}] Failed to finalize block {block_hash_hex[:8]}")

    def create_and_broadcast_transaction(self, recipient_id, cert_hash, issuer_id = None, db_id = None):
        timestamp = time()
        cert_hash_bytes = bytes.fromhex(cert_hash)
        sender_mid = self.my_peer.mid
        receiver_mid = b"api_receiver"
        message = sender_mid + receiver_mid + cert_hash_bytes + str(timestamp).encode()
        signature = default_eccrypto.create_signature(self.my_key, message)

        tx = Transaction(
            sender_mid=sender_mid,
            receiver_mid=receiver_mid,
            cert_hash=cert_hash_bytes,
            timestamp=timestamp,
            signature=signature,
            public_key=default_eccrypto.key_to_bin(self.my_key.pub())
        )

        self.broadcast(tx)
        print(f"[{self.node_id}] Transaction broadcasted: {cert_hash[:8]}")

    def create_and_broadcast_vote(self, block_hash: bytes, decision: str):
        decision_bytes = decision.encode()
        timestamp = time()
        msg = block_hash + self.my_peer.mid + decision_bytes + str(timestamp).encode()
        signature = default_eccrypto.create_signature(self.my_key, msg)

        vote = Vote(
            block_hash=block_hash,
            voter_mid=self.my_peer.mid,
            vote_decision=decision_bytes,
            timestamp=timestamp,
            signature=signature,
            public_key=default_eccrypto.key_to_bin(self.my_key.pub())
        )

        self.broadcast(vote)
        print(f"[{self.node_id}] Vote broadcasted: {decision} on block {block_hash.hex()[:8]}")

    def create_vote(self, block_hash: bytes, decision: str) -> Vote:
        decision_bytes = decision.encode()
        timestamp = time()
        msg = block_hash + self.my_peer.mid + decision_bytes + str(timestamp).encode()
        signature = default_eccrypto.create_signature(self.my_key, msg)

        vote = Vote(
            block_hash=block_hash,
            voter_mid=self.my_peer.mid,
            vote_decision=decision_bytes,
            timestamp=timestamp,
            signature=signature,
            public_key=default_eccrypto.key_to_bin(self.my_key.pub())
        )
        return vote




async def start_node(node_id, developer_mode, web_port=None):
    from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
    from ipv8.keyvault.crypto import ECCrypto
    from ipv8_service import IPv8

    builder = ConfigBuilder().clear_keys().clear_overlays()
    crypto = ECCrypto()
    key_path = f"key_{node_id}.pem"

    if not os.path.exists(key_path):
        key = crypto.generate_key("medium")
        with open(key_path, "wb") as f:
            f.write(key.key_to_bin())

    if developer_mode:
        print(f"🔑 Key loaded at {key_path}")

    port = 8090 + node_id
    if developer_mode:
        print(f"🌐 Port set at {port}")

    builder.add_key("my peer", "medium", key_path)
    builder.set_port(port)

    builder.add_overlay(
        "BlockchainCommunity",
        "my peer",
        walkers=[WalkerDefinition(Strategy.RandomWalk, 3.0, {"timeout": 3})],
        bootstrappers=default_bootstrap_defs,
        initialize={"anonymize": False},
        on_start=[]
    )

    from node import BlockchainCommunity  # make sure this is at the end to avoid circular import
    ipv8 = IPv8(builder.finalize(), extra_communities={"BlockchainCommunity": BlockchainCommunity})
    await ipv8.start()

    if developer_mode:
        print("✅ IPv8 started")

    # ✅ รอจน blockchain_community ถูกเซต
    global blockchain_community
    while blockchain_community is None:
        await asyncio.sleep(0.1)

    blockchain_community.started()
    print("✅ blockchain_community is ready!")
    return blockchain_community

    while True:
        await asyncio.sleep(1)