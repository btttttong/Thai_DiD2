from flask import Flask, request, jsonify
from threading import Thread
from node import start_node
from models.transaction import Transaction
from ipv8.keyvault.crypto import default_eccrypto
from binascii import unhexlify
import asyncio, time


app = Flask(__name__)
blockchain_community = None

def boot_node(node_id):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_node(node_id=node_id, developer_mode=True))
    loop.run_forever()

# Start 2 node in 2 threads
Thread(target=boot_node, args=(0,), daemon=True).start()
Thread(target=boot_node, args=(1,), daemon=True).start()

# ✅ Start node
Thread(target=boot_node, daemon=True).start()

# ✅ Wait for readiness
print("⏳ Waiting for blockchain_community...")
while blockchain_community is None:
    time.sleep(0.5)
print("✅ blockchain_community is ready!")
print("🔗 Node ID:", blockchain_community.title)

@app.route("/api/send_transaction", methods=["POST"])
def receive_transaction():
    tx_dict = request.json
    print("📩 Received tx:", tx_dict)

    try:
        print("🔍 Decoding fields...")
        signature = unhexlify(tx_dict["signature"])
        public_key = unhexlify(tx_dict["public_key"])
        message = f"{bytes.fromhex(tx_dict['receiver_mid']).decode()}|{bytes.fromhex(tx_dict['sender_mid']).decode()}|{tx_dict['db_id']}|{tx_dict['timestamp']}".encode("utf-8")
        print("🧾 Message for verification:", message)
        pk = default_eccrypto.key_from_public_bin(public_key)
        pk.verify(signature, message)
    except Exception as e:
        print(f"❌ Signature verification failed: {e}")
        return jsonify({"status": "failed", "reason": "Invalid signature"}), 400

    tx = Transaction(
        sender_mid=bytes.fromhex(tx_dict["sender_mid"]),
        receiver_mid=bytes.fromhex(tx_dict["receiver_mid"]),
        cert_hash=bytes.fromhex(tx_dict["cert_hash"]),
        db_id=tx_dict["db_id"],
        timestamp=tx_dict["timestamp"],
        signature=unhexlify(tx_dict["signature"]),
        public_key=unhexlify(tx_dict["public_key"]),
    )

    blockchain_community.blockchain.add_pending_transaction(tx)
    blockchain_community.broadcast(tx)

    return jsonify({"status": "received"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)