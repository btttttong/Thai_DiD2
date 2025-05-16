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

from webapp.app import NodeWeb

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
        # - Behavior switches -
        self.developer_mode = 1
        # (!) Troll master is active if you set it to "ACTIVE" explicitly
        self.troll_master = "ACTIVE"
        self.TTS_soul_snatcher = False

        # - Resistance components -
        # > Sybill switch <
        self.sybill_failsafe = True
        if self.sybill_failsafe == True:
            print("Sybil attack failsafe active")
        # > Double voting failsafe <
        self.double_voting_failsafe = True
        if self.double_voting_failsafe == True:
            print("Double voting failsafe active")
        # > Byzantine attack failsafe <
        self.byzantine_failsafe = False
        if self.byzantine_failsafe == True:
            print("Byzantine attack shield active")
        # > Message replay failsafe <
        self.message_replay_failsafe = True
        if self.message_replay_failsafe == True:
            print("Message replay failsafe active")
        # - key processing -
        self.my_key = default_eccrypto.key_from_private_bin(self.my_peer.key.key_to_bin())
        self.blockchain = Blockchain(max_block_size=5, validators=['Validator1'])
        self.known_peers = set()
        self.seen_message_hashes = set()
        self.my_key = default_eccrypto.key_from_private_bin(self.my_peer.key.key_to_bin())
        self.authorized_validator = self.my_peer.mid
        self.blockchain = Blockchain(max_block_size=10, validators=['Validator1' if self.sybill_failsafe == False else self.authorized_validator])
        self.sybil_attempts = []
        self.message_replay_violators = []
        self.hostile_byzantine_validators = []
        # - Cache storage -
        self.pending_transactions = []
        self.vote_collections = {}
        self.transactions = []
        self.node_id = None
        self.db = None
        self.current_proposed_block = None

    def broadcast(self, payload, exclude_peer=None):
        for peer in self.get_peers():
            if peer != exclude_peer and peer != self.my_peer:
                self.ez_send(peer, payload)

    def on_peer_added(self, peer: Peer) -> None:
        self.known_peers.add(peer.mid)
        print(f"[{self.my_peer.mid.hex()}] connected to {peer.mid.hex()}")

    def on_peer_removed(self, peer: Peer):
        print(f"[{self.node_id}] Peer {peer.mid.hex()} removed.")

    def started(self):
        self.network.add_peer_observer(self)
        self.add_message_handler(Transaction, self.on_transaction_received)
        self.add_message_handler(Vote, self.on_vote_received)

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
        print(f"[{self.node_id}] TX received from {tx.sender_mid.hex()[:6]} to {tx.receiver_mid.hex()[:6]}")
        self.broadcast(tx)

        print(f"[{self.node_id}] Pending transactions: {len(self.blockchain.pending_transactions)} / {self.blockchain.max_block_size}")
        if len(self.blockchain.pending_transactions) >= self.blockchain.max_block_size:
            self.propose_block()

    def voting_decision(self, block_hash: bytes, decision: str):
        # TODO: Implement the voting decision method
        if self.developer_mode == 1:
            print("Voting decision in progress")
        # <------------>
        accepted_choices = ["accept", "reject"]
        if decision not in accepted_choices:
            if self.developer_mode == 1:
                print("(!) Failure to make a decision")
            print(f"[{self.node_id}] Invalid decision -> '{decision}' must be '{accepted_choices[0]}' or '{accepted_choices[1]}'")
            return

        if decision == accepted_choices[0]:
            # > Accepted choices <
            self.create_and_broadcast_vote(block_hash=block_hash, decision=decision)
            if self.developer_mode == 1:
                print("Accepted broadcast signal completed")
        elif decision == accepted_choices[1]:
            # > Rejected choice <
            if self.developer_mode == 1:
                print("Rejection acknowledged. Broadcast dormant")
        # <------------>
        if self.developer_mode == 1:
            print("Voting decision has been made")

    def propose_block(self):
        if self.current_proposed_block is not None:
            print(f"[{self.node_id}] A block is already proposed: {self.current_proposed_block.hash[:8]}")
            return

        proposed_block = self.blockchain.propose_block()
        if proposed_block:
            self.current_proposed_block = proposed_block
            print(f"[{self.node_id}] Proposing Block {proposed_block.hash[:8]}")

            self.create_and_broadcast_vote(bytes.fromhex(proposed_block.hash), 'accept')

    def get_current_proposed_block(self):
        if self.current_proposed_block:
            return self.current_proposed_block.to_dict()
        return None

    def create_and_broadcast_transaction(self, recipient_id, issuer_id, cert_hash, db_id):
        timestamp = time()
        cert_hash_bytes = bytes.fromhex(cert_hash) if len(cert_hash) == 64 else cert_hash.encode()

        message = (
            self.my_peer.mid +
            b"api_receiver" +
            cert_hash_bytes +
            str(timestamp).encode()
        )

        signature = default_eccrypto.create_signature(self.my_key, message)

        transaction = Transaction(
            sender_mid=self.my_peer.mid,
            receiver_mid=b"api_receiver",
            cert_hash=cert_hash_bytes,
            timestamp=timestamp,
            signature=signature,
            public_key=default_eccrypto.key_to_bin(self.my_key.pub())
        )

        self.broadcast(transaction)

        print(f"[{self.node_id}] Transaction created and broadcasted: {cert_hash[:8]}")

        return {
            "recipient_id": recipient_id,
            "issuer_id": issuer_id,
            "cert_hash": cert_hash,
            "db_id": db_id,
            "timestamp": timestamp
        }

    @lazy_wrapper(Vote)
    def on_vote_received(self, peer: Peer, vote: Vote):
        block_hash_str = vote.block_hash.hex()

        # ✅ Ensure the collection exists before accessing it
        if block_hash_str not in self.vote_collections:
            self.vote_collections[block_hash_str] = []

        # ✅ Now it's safe to read existing votes
        existing_votes = [v for v in self.vote_collections[block_hash_str] if v.voter_mid == vote.voter_mid]

        vote_ID = hashlib.sha256(vote.block_hash + vote.voter_mid + vote.vote_decision + str(vote.timestamp).encode()).hexdigest()
        message_to_verify = vote.block_hash + vote.voter_mid + vote.vote_decision + str(vote.timestamp).encode()
        if not verify_signature(vote.signature, vote.public_key, message_to_verify):
            print(f"[{self.node_id}] Invalid Vote Signature from {peer.mid.hex()}")
            return

        # > Message replay failsafe <
        if self.message_replay_failsafe == True:
            if vote_ID in self.seen_message_hashes:
                print(f"[{self.node_id}] 🔁 Replay vote detected from {vote.voter_mid.hex()[:6]} on block {vote.block_hash.hex()[:6]}")
                self.message_replay_violators.append({
                    "Node ID": self.node_id,
                    "Voter_mid": vote.voter_mid.hex(),
                    "Block hash": vote.block_hash.hex(),
                    "Vote ID": vote_ID,
                    "Timestamp": time()
                    })
                if self.developer_mode == 1:
                    print("Violator has been documented")
                    if self.troll_master == "ACTIVE":
                        print("You think I didn't consider this? Nah. We take this seriously.")
                        print("Yours truly E3N_7274 has fucked your plan to resend your last vote ;)")

                return

            self.seen_message_hashes.add(vote_ID)

        # > Sybil protective failsafe <
        if self.sybill_failsafe == True:
            if vote.voter_mid != self.authorized_validator:
                ip_address_tracked = getattr(peer, "address", ("unknown",))[0]
                print(
                    f"[{self.node_id}] ❌ Unauthorized vote from {vote.voter_mid.hex()[:6]} at IP {ip_address_tracked}")
                if self.developer_mode == 1 and self.troll_master == "ACTIVE":
                    # > Call them out right here on sight <
                    print(f"\nSybil vote attack documented. You are done {self.node_id}\n")

                self.sybil_attempts.append({
                    "Voter mid": vote.voter_mid.hex(),
                    "Tracked IP address": ip_address_tracked,
                    "Block_Hash": vote.block_hash.hex(),
                    "Time stamp": time()
                    })
                return

        # > Byzantine contradiction failsafe <
        if self.byzantine_failsafe == True:
            if existing_votes and vote.vote_decision != existing_votes[0].vote_decision:
                print(f"[{self.node_id}] ⚠️ Byzantine behavior detected from {vote.voter_mid.hex()[:6]} on block {vote.block_hash.hex()[:6]}")
                self.hostile_byzantine_validators.append({
                    "Node ID": self.node_id,
                    "Voter mid": vote.block_hash.hex(),
                    "Block hash": existing_votes[0].vote_decision.decode(),
                    "Existing vote": vote.vote_decision.decode(),
                    "Conflicting vote": vote.vote_decision.decode(),
                    "Timestamp": time()
                    })
                if self.developer_mode == 1:
                    print("Hostile byzantine validator identified and logged.")
                    if self.troll_master == "ACTIVE":
                        print("Im sorry you think we didn't plan for you?!?!?!\n🖕")
                        print("I DECLARE YOU SHALL NOT PASS")

                return

        block_hash_str = vote.block_hash.hex()
        if block_hash_str not in self.vote_collections:
            self.vote_collections[block_hash_str] = []

        voter_mids = [v.voter_mid for v in self.vote_collections[block_hash_str]]
        if self.double_voting_failsafe == False:
            # > Double voting failsafe inactive <
            if vote.voter_mid not in voter_mids:
                self.vote_collections[block_hash_str].append(vote)
        elif self.double_voting_failsafe == True:
            # > Double voting failsafe active <
            if vote.voter_mid not in voter_mids:
                # > Processes vote <
                self.vote_collections[block_hash_str].append(vote)
            elif vote.voter_mid in voter_mids:
                # > Ceases processing of vote if already voted <
                if self.troll_master == "ACTIVE":
                    print(f"\n[{self.node_id}] ⚠️ Double voting attempt by {vote.voter_mid.hex()[:6]} on block {block_hash_str[:6]}")
                else:
                    print(f"[{self.node_id}] ⚠️ Double voting attempt by {vote.voter_mid.hex()[:6]} on block {block_hash_str[:6]}")

                if self.troll_master == "ACTIVE":
                    print("Is this you trying to double vote? -_-")
                    print(f"Bad news for you I planned for this kind of nonsense. This shall not pass.\n🖕\n")
                return

        print(f"[{self.node_id}] Received Vote {vote.vote_decision.decode()} from {vote.voter_mid.hex()[:6]} on Block {block_hash_str[:6]}")

        # Check if we have 3 accepts
        if sum(1 for v in self.vote_collections[block_hash_str] if v.vote_decision == b'accept') >= 3:
            self.finalize_block(block_hash_str)

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

        print(f"[{self.node_id}] Voting {decision} on Block {block_hash.hex()[:8]}")
        self.broadcast(vote)

    def finalize_block(self, block_hash_hex: str):
        block = self.blockchain.get_proposed_block(block_hash_hex)
        if block:
            self.blockchain.finalize_block(block_hash_hex, validator='Validator1')
            self.current_proposed_block = None 
            print(f"[{self.node_id}] Block {block_hash_hex[:8]} finalized!")

            if len(self.blockchain.pending_transactions) >= self.blockchain.max_block_size:
                self.propose_block()
        else:
            print(f"[{self.node_id}] Block {block_hash_hex[:8]} not found.")

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
            
            if web_port is not None:
                community = ipv8.get_overlay(BlockchainCommunity)
                community.node_id = node_id
                #community.db = CertDBHandler(node_id)
                community.web = NodeWeb(community, port=web_port)
                
                # Run Flask in a separate thread properly
                flask_thread = Thread(
                    target=community.web.start,
                    daemon=True  # Daemonize so it exits with main thread
                )
                flask_thread.start()
            
            # Keep the node running
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            print("Shutting down node...")
        finally:
            await ipv8.stop()
            try:
                os.unlink(key_path)
            except:
                pass
                
    asyncio.run(boot())

