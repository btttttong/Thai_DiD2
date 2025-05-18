import asyncio
import hashlib
import json
from time import time
from node import start_node
from models.transaction import Transaction

async def simulate_tx():
    community = await start_node(node_id=4, developer_mode=True)
    await asyncio.sleep(10)  # รอ peer discover
    print(f"Connected peers: {[p.mid.hex()[:6] for p in community.get_peers()]}")

    recipient_id = "stu123"
    issuer_id = "uniABC"
    db_id = "db001"
    cert_hash = hashlib.sha256(f"{recipient_id}:{issuer_id}:{db_id}:{time()}".encode()).hexdigest()

    sender_mid = community.my_peer.mid.hex()
    tx = Transaction(sender_mid, recipient_id, cert_hash, "", "", db_id)
    tx.sign(community.my_key)

    tx_json = json.dumps(tx.to_dict()).encode()
    print(f"📩 Sending TX JSON: {tx_json}")

    # manual gossip แบบ raw
    for peer in community.get_peers():
        print(f"Found peer: {peer.mid.hex()} @ {peer.address} vs self: {community.my_peer.mid.hex()} @ {community.endpoint.get_address()}")
        if peer != community.my_peer:
            print(f"🚀 Sending to peer {peer.mid.hex()[:6]}")
            community.endpoint.send(peer.address, b"\x01" + tx_json)

    print("⏳ Waiting for peers to process the TX...")
    await asyncio.sleep(20)  # รอ peer ประมวลผลให้ครบ
    print("✅ TX propagation wait complete.")
    print(f"✅ Simulated TX sent: {cert_hash[:8]}")

if __name__ == "__main__":
    asyncio.run(simulate_tx())