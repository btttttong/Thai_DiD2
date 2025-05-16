from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
import sqlite3
import random

@dataclass
class Certificate:
    cert_id: str
    user_public_key: str  # Foreign key to User
    cert_hash: str
    issuer: str = "authority"
    issued_at: str = datetime.utcnow().isoformat()

class CertificateRepository:
    def __init__(self, db_path="users.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_table()
        self.certs_db = {
            "greater": {

                "certificates": [  # list of cert dicts for this user
                    {
                        "hash": "abc123",
                        "recipient": "greater",
                        "issuer": "authority",
                        "timestamp": 1680000000
                    },
                    {
                        "hash": "def456",
                        "recipient": "greater",
                        "issuer": "authority",
                        "timestamp": 1685000000
                    }
                ]
            }
        }

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS certificates (
            cert_id TEXT PRIMARY KEY,
            user_public_key TEXT NOT NULL,
            cert_hash TEXT NOT NULL,
            issuer TEXT,
            issued_at TEXT
        )
        """
        # FOREIGN KEY(user_public_key) REFERENCES users(public_key)
        self.conn.execute(query)
        self.conn.commit()

    def add_certificate(self, cert: Certificate):
        if cert.user_public_key not in self.certs_db:
            self.certs_db[cert.user_public_key] = {"certificates": []}
        self.certs_db[cert.user_public_key]["certificates"].append(
            {
                "hash":cert.cert_hash,
                "recipient":cert.user_public_key,
                "issuer":cert.issuer,
                "timestamp":random.randint(1680000000, 1685000000)
            }
        )
        # query = """
        # INSERT OR REPLACE INTO certificates (cert_id, user_public_key, cert_hash)
        # VALUES (?, ?, ?, ?)
        # """
        # self.conn.execute(query, (cert.cert_id, cert.user_public_key, cert.cert_hash))
        # self.conn.commit()


    def get_certificates_by_user(self, public_key: str):
        # cursor = self.conn.execute("SELECT * FROM certificates WHERE public_key = ?", (public_key,))
        # rows = cursor.fetchall()
        # certs = []
        # for row in rows:
        #     print(row)
        #     cert = {
                
        #     }

        user_certs = self.certs_db.get(public_key)
        if user_certs is None:
            return []
        return user_certs.get("certificates", [])
    

    def get_all_certificates(self) -> List[Certificate]:
        cursor = self.conn.execute("SELECT * FROM certificates")
        rows = cursor.fetchall()
        return [Certificate(*row) for row in rows]

    def close(self):
        self.conn.close()
