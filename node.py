import os, json, asyncio, hashlib
from random import choice
from time import time
from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
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
from models.blockpayload import BlockPayload


def verify_signature(signature: bytes, public_key: bytes, message: bytes) -> bool:
    try:
        pk = default_eccrypto.key_from_public_bin(public_key)
        pk.verify(signature, message)
        return True
    except InvalidSignature:
        return False

def block_to_payload(block: Block) -> BlockPayload:
    tx_jsons = [tx.to_dict() for tx in block.transactions]
    tx_bytes = json.dumps(tx_jsons).encode('utf-8')

    return BlockPayload(
        index=block.index,
        previous_hash=block.previous_hash.encode('utf-8') if isinstance(block.previous_hash, str) else block.previous_hash,
        transactions=tx_bytes,
        signature=block.signature,
        public_key=block.public_key,
        db_id=b"default_db_id",
    )

def payload_to_block(payload: BlockPayload) -> Block:
    tx_dicts = json.loads(payload.transactions.decode('utf-8'))
    tx_list = [Transaction.from_dict(d) for d in tx_dicts]

    return Block(
        index=payload.index,
        previous_hash=payload.previous_hash.decode('utf-8'),
        transactions=tx_list,
        signature=payload.signature,
        public_key=payload.public_key
    )


class BlockchainCommunity(Community, PeerObserver):
    community_id = b"myblockchain-test-01"

    def get_my_message_handlers(self):
        print(f"[{getattr(self, 'node_id', '??')}] 🔧 Handler registered")
        # return {b"\x01": self.on_transaction_packet}
        return getattr(self, "custom_message_handlers", {})


    def __init__(self, settings: CommunitySettings):
        print(f"[{self.__class__.__name__}] Handler registration (check): {hasattr(self, 'get_my_message_handlers')}")

        super().__init__(settings)
        self.my_key = default_eccrypto.key_from_private_bin(self.my_peer.key.key_to_bin())
        self.known_peers = set()
        self.seen_message_hashes = set()
        self.vote_collections = {}
        self.node_id = None
        self.current_proposed_block = None

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
                print(f"[{self.node_id}] 🚀 Gossip to {peer.mid.hex()[:6]}")
                self.ez_send(peer, payload)

    def on_peer_added(self, peer: Peer):
        self.known_peers.add(peer.mid)
        print(f"[{self.my_peer.mid.hex()}] connected to {peer.mid.hex()}")

    def on_peer_removed(self, peer: Peer):
        self.known_peers.discard(peer.mid)
        print(f"[{self.my_peer.mid.hex()}] disconnected from {peer.mid.hex()}")

    async def send_transaction(self):
        recipient_id = "stu123"
        issuer_id = "uniABC"
        db_id = "db001"
        cert_hash = hashlib.sha256(f"{recipient_id}:{issuer_id}:{db_id}:{time()}".encode()).hexdigest()

        self.create_and_broadcast_transaction(
            recipient_id=recipient_id,
            issuer_id=issuer_id,
            cert_hash=cert_hash,
            db_id=db_id
        )

    async def heartbeat(self):
        while True:
            print(f"[{self.node_id}] ❤️ Alive, peers: {len(self.get_peers())}")
            await asyncio.sleep(5)

    def started(self):
        self.node_id = self.my_peer.mid.hex()[:6]
        print(f"🚀 Node started with MID: {self.my_peer.mid.hex()}")
        print(f"📛 Role will be loaded from node_config.json (if available)")
        self.network.add_peer_observer(self)
        self.custom_message_handlers = {b"\x01": self.on_transaction_packet}
        # self.add_message_handler(Transaction, self.on_transaction_received)
        self.add_message_handler(Vote, self.on_vote_received)
        self.add_message_handler(BlockPayload, self.on_block_payload_received)
        # self.add_message_handler(b"\x01", self.on_transaction_packet)

        self.role = self.load_node_role()
        self.validators = self.load_validators()
        self.register_task("heartbeat", self.heartbeat, interval=9999, delay=0)
        print(f"[{self.node_id}] Connected peers: {[p.mid.hex()[:6] for p in self.get_peers()]}")

        # if self.role == "sender":
        #     self.register_task("dummy_broadcast", self.send_dummy_payloads, interval=9999, delay=5)  # runs once after 5s
        #     self.register_task("send_transaction", self.send_transaction_loop, interval=5, delay=10)  # every 5s after 10s


    async def send_dummy_payloads(self):
        # Dummy TX
        self.create_and_broadcast_transaction(
            recipient_id="dummy",
            cert_hash=hashlib.sha256(b"dummy:uniABC:db001:" + str(time()).encode()).hexdigest(),
            db_id="db001"
        )
        print(f"[{self.node_id}] Dummy transaction broadcasted")

        # Dummy Block
        dummy_block = Block(
            index=0,
            previous_hash="0",
            transactions=[],  # Empty transactions for dummy
            signature=b"dummy_signature",
            public_key=b"dummy_public_key"
        )
        print(f"[{self.node_id}] Dummy block broadcasted: {dummy_block.hash[:8]}")
        self.broadcast_block(dummy_block)

        self.cancel_pending_task("dummy_broadcast")
        print(f"[{self.node_id}] Dummy broadcast task completed and cancelled.")


    async def send_transaction_loop(self):
        self.create_and_broadcast_transaction(
            recipient_id="stu123",
            cert_hash=hashlib.sha256(b"stu123:uniABC:db001:" + str(time()).encode()).hexdigest(),
            db_id="db001"
        )
        print(f"[{self.node_id}] Regular transaction broadcasted")

    def log_peers(self):
        print(f"[{self.node_id}] Known peers: {len(self.known_peers)} | Connected peers: {len(self.get_peers())}")

    # @lazy_wrapper(Transaction)
    # def on_transaction_received(self, peer: Peer, tx: Transaction):
    #     message_id = hashlib.sha256(tx.cert_hash).hexdigest()
    #     if message_id in self.seen_message_hashes:
    #         return

    #     self.seen_message_hashes.add(message_id)
    #     if not verify_signature(tx.signature, tx.public_key,
    #                             tx.sender_mid + tx.receiver_mid + tx.cert_hash):
    #         print(f"[{self.node_id}] Invalid TX from {peer.mid.hex()}")
    #         return

    #     self.blockchain.add_pending_transaction(tx)
    #     print(f"[{self.node_id}] TX received from {tx.sender_mid.hex()[:6]} to {tx.receiver_mid.hex()[:6]} pending: {len(self.blockchain.pending_transactions)}")
    #     self.broadcast(tx)

    #     if len(self.blockchain.pending_transactions) >= self.blockchain.max_block_size:
    #         print(f"[{self.node_id}] Block size reached, proposing block...")
    #         self.propose_block()

    @lazy_wrapper(Transaction)
    def on_transaction(self, peer: Peer, payload: Transaction):
        print(f"📩 Transaction from {payload.sender} to {payload.receiver}: {payload.message}")
        # ส่งกลับไปหาคนอื่น (gossip)
        self.ez_send(peer, Transaction(payload.sender, payload.receiver, payload.message))

    def propose_block(self):
        if self.role != "validator" or not self.is_my_turn():
            return
        if self.current_proposed_block is not None:
            return

        block = self.blockchain.propose_block(private_key=self.my_key)
        if block:
            self.current_proposed_block = block
            print(f"[{self.node_id}] Proposing Block {block.hash[:8]}")
            self.broadcast_block(block)

    def broadcast_block(self, block: Block):
        block_payload = block_to_payload(block)
        for peer in self.get_peers():
            if peer != self.my_peer:
                self.ez_send(peer, block_payload)
        print(f"[{self.node_id}] Block broadcasted: {block.hash[:8]}")

    def broadcast_finalized_block(self, block: Block):
        block_payload = block_to_payload(block)
        for peer in self.get_peers():
            if peer != self.my_peer:
                self.ez_send(peer, block_payload)
        print(f"[{self.node_id}] Finalized block broadcasted: {block.hash.hex()[:8]}")

    @lazy_wrapper(BlockPayload)
    def on_block_payload_received(self, peer: Peer, block_payload: BlockPayload):
        block = payload_to_block(block_payload)

        if block.hash.startswith("dummy"):
            return
        if block.hash in self.seen_message_hashes:
            return

        print(f"[{self.node_id}] Received block from {peer.mid.hex()[:6]}: {block.hash[:8]}")
        self.seen_message_hashes.add(block.hash)

        if not verify_signature(block.signature, block.public_key, block.get_bytes()):
            print(f"[{self.node_id}] Invalid block signature")
            return

        if not self.blockchain.validate_block(block):
            print(f"[{self.node_id}] Invalid block content")
            return

        self.blockchain.store_proposed_block(block)

    @lazy_wrapper(Vote)
    def on_vote_received(self, peer: Peer, vote: Vote):
        block_hash_str = vote.block_hash.hex()
        print(f"[{self.node_id}] Received vote from {vote.voter_mid.hex()[:6]} on block {block_hash_str[:8]}")

        if block_hash_str not in self.vote_collections:
            self.vote_collections[block_hash_str] = []

        if not verify_signature(
            vote.signature,
            vote.public_key,
            vote.block_hash + vote.voter_mid + vote.vote_decision
        ):
            print(f"[{self.node_id}] Invalid vote signature")
            return

        if vote.voter_mid not in [v.voter_mid for v in self.vote_collections[block_hash_str]]:
            self.vote_collections[block_hash_str].append(vote)

        accept_votes = sum(1 for v in self.vote_collections[block_hash_str] if v.vote_decision == b'accept')
        print(f"[{self.node_id}] Total accept votes: {accept_votes}")

        if accept_votes >= 3:
            print(f"[{self.node_id}] Vote threshold reached for block {block_hash_str[:8]}")
            self.finalize_block(block_hash_str)

    def finalize_block(self, block_hash_hex: str):
        block = self.blockchain.get_proposed_block(block_hash_hex)
        if block:
            success = self.blockchain.finalize_block(block_hash_hex, validator=self.my_peer.mid.hex())
            if success:
                self.current_proposed_block = None
                print(f"[{self.node_id}] Block finalized: {block_hash_hex[:8]}")
                self.broadcast_finalized_block(block)

    def create_and_broadcast_transaction(self, recipient_id, issuer_id, cert_hash, db_id):
        sender_mid = self.my_peer.mid.hex()
        receiver_mid = recipient_id
        msg = sender_mid + receiver_mid + cert_hash + db_id
        signature = self.my_key.sign(msg.encode()).hex()
        public_key = self.my_key.public_key.key_to_bin().hex()
        tx = Transaction(sender_mid, receiver_mid, cert_hash, signature, public_key, db_id)
        tx_json = json.dumps(tx.to_dict()).encode()
        self.broadcast(b"\x01" + tx_json)
        print(f"[{self.node_id}] Transaction broadcasted: {cert_hash[:8]}")


    def on_transaction_packet(self, peer: Peer, data: bytes):
        print(f"[{self.node_id}] 🧨 on_transaction_packet called")
        print(f"[{self.node_id}] 🧨 PACKET received raw: {data}")
        try:
            tx_data = json.loads(data[1:].decode())
            tx = Transaction.from_dict(tx_data)
            print(f"[{self.node_id}] 📥 Received TX from {tx.sender_mid[:6]} → {tx.receiver_mid[:6]}")
            message_id = hashlib.sha256(tx.cert_hash.encode()).hexdigest()
            if message_id in self.seen_message_hashes:
                print(f"[{self.node_id}] 🔁 TX already seen: {message_id[:8]}")
                return
            self.seen_message_hashes.add(message_id)
            msg = tx.sender_mid + tx.receiver_mid + tx.cert_hash + tx.db_id
            if not verify_signature(bytes.fromhex(tx.signature), bytes.fromhex(tx.public_key), msg.encode()):
                print(f"[{self.node_id}] Invalid TX signature")
                return
            self.blockchain.add_pending_transaction(tx)
            print(f"[{self.node_id}] TX received from {tx.sender_mid[:6]} to {tx.receiver_mid[:6]}")
            self.broadcast(b"\x01" + data[1:], exclude_peer=peer)
            if len(self.blockchain.pending_transactions) >= self.blockchain.max_block_size:
                self.propose_block()
        except Exception as e:
            print(f"[{self.node_id}] TX decode error: {e}")


async def start_node(node_id, developer_mode, web_port=None):
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

    ipv8 = IPv8(builder.finalize(), extra_communities={"BlockchainCommunity": BlockchainCommunity})
    await ipv8.start()
    community = ipv8.overlays[0]
    community.started()
    return community
