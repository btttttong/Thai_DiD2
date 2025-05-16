import json
import random
import hashlib
import string
import requests
from time import time

API_URL = "http://localhost:8080/api/send_transaction"

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_transaction():
    recipient_id = random_string(8)
    issuer_id = random_string(8)
    db_id = random_string(12)
    cert_content = f"{recipient_id}:{issuer_id}:{db_id}:{time()}"
    cert_hash = hashlib.sha256(cert_content.encode()).hexdigest()
    #TODO: sign tx
    
    return {
        "recipient_id": recipient_id,
        "issuer_id": issuer_id,
        "cert_hash": cert_hash,
        "db_id": db_id
    }

def send_transaction(transaction):
    response = requests.post(API_URL, json=transaction)
    if response.ok:
        print(f"✅ Sent: {transaction}")
    else:
        print(f"❌ Failed to send: {response.text}")

if __name__ == "__main__":
    for _ in range(10):  # Change to any number of transactions you want to send
        tx = generate_transaction()
        send_transaction(tx)
