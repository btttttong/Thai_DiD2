from flask import Flask, request, jsonify
from binascii import unhexlify
from ipv8.keyvault.crypto import default_eccrypto
from models.transaction import Transaction
import time

# Import the blockchain_community instance started in main.py
from main import blockchain_community

app = Flask(__name__)

@app.route("/api/send_transaction", methods=["POST"])
def receive_transaction():
    tx_dict = request.json
    print("📩 Received tx:", tx_dict)

    try:
        signature = unhexlify(tx_dict["signature"])
        public_key = unhexlify(tx_dict["public_key"])
        pk = default_eccrypto.key_from_public_bin(public_key)

        recipient_id = str(tx_dict["recipient_id"])
        issuer_id = str(tx_dict["issuer_id"])
        db_id = str(tx_dict["db_id"])
        timestamp = str(tx_dict["timestamp"])

        message = f"{recipient_id}|{issuer_id}|{db_id}|{timestamp}".encode("utf-8")
        pk.verify(signature, message)

        tx = Transaction(
            recipient_id=recipient_id,
            issuer_id=issuer_id,
            db_id=db_id,
            signature=signature,
            public_key=public_key,
            timestamp=float(timestamp)
        )

        if blockchain_community:
            blockchain_community.on_transaction_received(None, tx)
            return jsonify({"status": "Transaction accepted"}), 200
        else:
            return jsonify({"error": "Blockchain not ready"}), 503

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    print("✅ API ready at http://localhost:8080")
    app.run(port=8080)