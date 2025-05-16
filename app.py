from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/send_transaction', methods=['POST'])
def receive_transaction():
    tx = request.json
    print("Received tx:", tx)
    # TODO: verify และส่งต่อไปยังระบบ blockchain community
    return jsonify({"status": "received"}), 200

if __name__ == '__main__':
    app.run(port=8080)
