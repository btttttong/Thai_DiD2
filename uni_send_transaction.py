import json
import random
import hashlib
import string
from time import time
from ipv8.keyvault.crypto import default_eccrypto, ECCrypto
import requests
from models.transaction import Transaction

API_URL = "http://localhost:8080/api/send_transaction"

crypto = ECCrypto()
key = crypto.generate_key("medium")  # หรือโหลด key จากไฟล์ของ uni

def serialize_message_for_signature(recipient_id: str, issuer_id: str, db_id: str) -> bytes:
    """
    สร้างข้อความที่ใช้สำหรับเซ็นและตรวจสอบลายเซ็น
    รูปแบบ: "recipient_id|issuer_id|db_id|timestamp"
    """
    message_str = f"{recipient_id}|{issuer_id}|{db_id}"
    return message_str.encode('utf-8')

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_transaction():
    recipient_id = random_string(8).encode()
    issuer_id = random_string(8).encode()
    db_id = random_string(12)

    cert_content = b"%b:%b:%s:%d" % (
        recipient_id, issuer_id, db_id.encode(), int(time())
    )
    cert_hash = hashlib.sha256(cert_content).digest()

    tx = Transaction(
        sender_mid=issuer_id,
        receiver_mid=recipient_id,
        cert_hash=cert_hash,
        db_id=db_id
    )
    tx.sign(key)

    return tx.to_dict()

def send_transaction(transaction):
    response = requests.post(API_URL, json=transaction)
    if response.ok:
        print(f"✅ Sent: {transaction}")
    else:
        print(f"❌ Failed to send: {response.text}")

if __name__ == "__main__":
    for _ in range(1):
        tx = generate_transaction()
        send_transaction(tx)
