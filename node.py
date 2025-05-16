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
from ipv8.lazy_community import lazy_wrapper


from models.transaction import Transaction
from models.blockchain import Blockchain
from models.vote import Vote
from models.block import Block


"""
uni: create tx
uni: sign tx with private key
uni: send tx to network

nw: receive tx (on_transaction_received)
nw: verify tx signature (on_transaction_received)
nw: broadcast tx to network (gossip tx)

validator: receive tx and store in mempool (pending)

proposer: check if it's their turn (round-robin or rule)
proposer: collect txs from mempool
proposer: create block
proposer: sign block with private key
proposer: broadcast block to validator set

validator: receive proposed block
validator: verify block signature and contents
validator: create vote
validator: sign vote with private key
validator: sent vote to proposer
proposer: collect votes
proposer: if vote threshold reached → commit block
proposer: broadcast committed block

user: receive cert or confirmation (off-chain or on-chain response)
"""

# blockchain_community_poav2.py

import os, json, asyncio, hashlib
from time import time
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.peerdiscovery.network import PeerObserver
from ipv8.types import Peer
from ipv8_service import IPv8
from ipv8.keyvault.crypto import default_eccrypto, ECCrypto
from cryptography.exceptions import InvalidSignature
from models.transaction import Transaction
from models.blockchain import Blockchain
from models.vote import Vote


def verify_signature(signature: bytes, public_key: bytes, message: bytes) -> bool:
    try:
        pk = default_eccrypto.key_from_public_bin(public_key)
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False

class BlockchainCommunity(Community, PeerObserver):
    community_id = b"myblockchain-test-01"

    def __init__(self, settings: CommunitySettings):
        super().__init__(settings)
        self.my_key = default_eccrypto.key_from_private_bin(self.my_peer.key.key_to_bin())
        self.known_peers = set()
        self.seen_message_hashes = set()
        self.vote_collections = {}
        self.node_id = None
        self.current_proposed_block = None

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
        self.node_id = self.my_peer.mid.hex()[:6]
        self.network.add_peer_observer(self)
        self.add_message_handler(Transaction, self.on_transaction_received)
        self.add_message_handler(Vote, self.on_vote_received)

        async def send_transaction():
            await asyncio.sleep(5)
    
            self.create_and_broadcast_transaction(
                recipient_id="stu123",
                issuer_id="uniABC",
                cert_hash=hashlib.sha256(b"stu123:uniABC:db001:" + str(time()).encode()).hexdigest(),
                db_id="db001"
            )

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
        for peer in self.get_peers():
            if peer != self.my_peer:
                self.ez_send(peer, block)
        print(f"[{self.node_id}] Block broadcasted: {block.hash.hex()[:8]}")


    def propose_block(self):
        if self.role != "validator" or not self.is_my_turn():
            return
        if self.current_proposed_block is not None:
            return

        block = self.blockchain.propose_block(private_key=self.my_key)
        print(f"[{self.node_id}] Proposed Block: {block.hash.hex()[:8]}")
        if block:
            self.current_proposed_block = block
            print(f"[{self.node_id}] Proposing Block {block.hash[:8]}")
            self.broadcast_block(block)  # Broadcast block แทน vote ก่อน
            # Proposer ก็ vote ตัวเองด้วย
            vote = self.create_vote(block.hash, 'accept')
            self.broadcast(vote)

    def broadcast_finalized_block(self, block: Block):
        for peer in self.get_peers():
            if peer != self.my_peer:
                self.ez_send(peer, block)
        print(f"[{self.node_id}] Finalized block broadcasted: {block.hash.hex()[:8]}")



    
    @lazy_wrapper(Block)  # สมมติ Block class อยู่ในโมดูลของคุณ
    def on_block_received(self, peer: Peer, block: Block):
        block_hash_hex = block.hash.hex()
        if block_hash_hex in self.seen_message_hashes:
            return  # บล็อกซ้ำ

        self.seen_message_hashes.add(block_hash_hex)

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
        vote = self.create_vote(block.hash, 'accept')
        self.broadcast(vote)
        print(f"[{self.node_id}] Vote sent for block {block_hash_hex[:8]}")
    
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

    def create_and_broadcast_transaction(self, recipient_id, issuer_id, cert_hash, db_id):
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


def start_node(node_id, developer_mode, web_port=None):
    async def boot():
        builder = ConfigBuilder().clear_keys().clear_overlays()
        crypto = ECCrypto()
        key_path = f"key_{node_id}.pem"
        if not os.path.exists(key_path):
            key = crypto.generate_key("medium")
            with open(key_path, "wb") as f:
                f.write(key.key_to_bin())
        if developer_mode == True:
            print(f"Key generated/loaded at {key_path}")

        port_offset = int(os.environ.get("PORT_OFFSET", "0"))
        port = 8090 + port_offset
        if developer_mode == True:
            print(f"Port set at {port}")

        generation_status = "medium"
        alias_status = "my peer"
        builder.add_key(alias_status, generation_status, key_path)
        builder.set_port(port)
        if developer_mode == True:
            print(f"Builder set at port {port}, generation status of '{generation_status}' and alias status of '{alias_status}'")

        builder.add_overlay("BlockchainCommunity", "my peer",
                          [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})],
                          default_bootstrap_defs, {}, [('started', )])

        ipv8 = IPv8(builder.finalize(), extra_communities={'BlockchainCommunity': BlockchainCommunity})
        if developer_mode == True:
            print("IPV8 finalized. Deployment cleared.")

        try:
            await ipv8.start()
            
            # if web_port is not None:
            #     community = ipv8.get_overlay(BlockchainCommunity)
            #     community.node_id = node_id
            #     #community.db = CertDBHandler(node_id)
            #     community.web = NodeWeb(community, port=web_port)
                
            #     # Run Flask in a separate thread properly
            #     flask_thread = Thread(
            #         target=community.web.start,
            #         daemon=True  # Daemonize so it exits with main thread
            #     )
            #     flask_thread.start()
            
            # Keep the node running
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            print("Shutting down node...")
        finally:
            await ipv8.stop()
                
    asyncio.run(boot())

