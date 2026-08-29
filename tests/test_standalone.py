import base64
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import sys

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import db  # noqa: E402
import engine  # noqa: E402
import app  # noqa: E402


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

    def test_quota_http_402_is_deactivation(self):
        class Response:
            status_code = 402
            text = '{"detail":"payment required"}'

        class Session:
            def get(self, *args, **kwargs):
                return Response()

        with mock.patch.object(engine, "create_http_session", return_value=Session()):
            with self.assertRaises(engine.AccountDeactivated) as caught:
                engine.fetch_quota({"email": "x@example.com", "access_token": "at"})
        self.assertEqual(caught.exception.status_code, 402)

    def test_login_http_403_is_deactivation(self):
        class Flow:
            def __init__(self, *args, **kwargs):
                self.result = type("Result", (), {})()

            def run_protocol_login(self, *args, **kwargs):
                raise RuntimeError("密码登录失败: 403 - account disabled")

        with mock.patch.object(engine, "AuthFlow", Flow):
            with self.assertRaises(engine.AccountDeactivated) as caught:
                engine.relogin_account({
                    "email": "x@example.com",
                    "password": "password",
                    "totp_secret": "JBSWY3DPEHPK3PXP",
                })
        self.assertEqual(caught.exception.status_code, 403)

    def test_workspace_402_marks_all_matching_accounts(self):
        first = db.upsert_account({
            "email": "one@example.com",
            "password": "p",
            "totp_secret": "t",
            "chatgpt_account_id": "workspace-1",
        })
        second = db.upsert_account({
            "email": "two@example.com",
            "password": "p",
            "totp_secret": "t",
            "chatgpt_account_id": "workspace-1",
        })
        with app._jobs_lock:
            app._workspace_402.clear()
            app._jobs["test-job"] = {
                "items": [
                    {"account_id": first["id"], "status": "running"},
                    {"account_id": second["id"], "status": "pending"},
                ],
                "done": 0,
                "success": 0,
                "failed": 0,
            }
        app._mark_workspace_402("test-job", "workspace-1", "账号停用/不可用 HTTP 402")
        self.assertEqual(db.get_account(first["id"])["status"], "402")
        self.assertEqual(db.get_account(second["id"])["status"], "402")
        self.assertEqual(app._jobs["test-job"]["failed"], 2)
        with app._jobs_lock:
            app._jobs.pop("test-job", None)


if __name__ == "__main__":
    unittest.main()
