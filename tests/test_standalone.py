import base64
import json
import tempfile
import unittest
from pathlib import Path

import sys

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import db  # noqa: E402
import engine  # noqa: E402


def jwt(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


class StandaloneTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.temp_dir.name) / "relogin.sqlite3"
        db.init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sub2_credentials_are_normalized(self):
        access = jwt({
            "sub": "user-1",
            "https://api.openai.com/auth": {"chatgpt_account_id": "acct-1"},
            "https://api.openai.com/profile": {"email": "User@Example.com"},
        })
        row = engine.normalized_account({
            "credentials": {
                "access_token": access,
                "refresh_token": "rt",
                "id_token": "id",
                "password": "pass",
                "totp_secret": "JBSWY3DPEHPK3PXP",
            }
        })
        self.assertEqual(row["email"], "user@example.com")
        self.assertEqual(row["chatgpt_account_id"], "acct-1")
        self.assertEqual(row["password"], "pass")

    def test_proxy_import_count_and_least_used_rotation(self):
        self.assertEqual(db.add_proxies(["http://one", "http://two", "http://one"]), 2)
        first, _, first_count = db.lease_proxy()
        second, _, second_count = db.lease_proxy(exclude=first)
        self.assertNotEqual(first, second)
        self.assertEqual(first_count, 1)
        self.assertEqual(second_count, 1)


if __name__ == "__main__":
    unittest.main()

