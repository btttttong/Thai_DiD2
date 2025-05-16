import json
import random
import hashlib
import string
from time import time
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.keyvault.crypto import ECCrypto
import requests  # อย่าลืมติดตั้ง requests ด้วย pip

API_URL = "http://localhost:8080/api/send_transaction"

crypto = ECCrypto()
key = crypto.generate_key("medium")  # หรือโหลด key จากไฟล์ของ uni

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_transaction():
    recipient_id = random_string(8)
    issuer_id = random_string(8)
    db_id = random_string(12)
    cert_content = f"{recipient_id}:{issuer_id}:{db_id}:{time()}"
    cert_hash = hashlib.sha256(cert_content.encode()).hexdigest()

    # เตรียม message bytes สำหรับเซ็น
    message = (recipient_id + issuer_id + db_id + str(time())).encode()

    # เซ็น message ด้วย private key
    signature = default_eccrypto.create_signature(key, message)
    public_key = default_eccrypto.key_to_bin(key.pub())

    return {
        "recipient_id": recipient_id,
        "issuer_id": issuer_id,
        "cert_hash": cert_hash,
        "db_id": db_id,
        "signature": signature.hex(),
        "public_key": public_key.hex(),
    }

def send_transaction(transaction):
    response = requests.post(API_URL, json=transaction)
    if response.ok:
        print(f"✅ Sent: {transaction}")
    else:
        print(f"❌ Failed to send: {response.text}")

if __name__ == "__main__":
    for _ in range(10):
        tx = generate_transaction()
        send_transaction(tx)
