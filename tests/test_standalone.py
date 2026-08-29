import base64
import json
import tempfile
import unittest
import uuid
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

    def test_cpa_export_uses_current_tokens(self):
        row = db.upsert_account({
            "email": "cpa@example.com",
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "id_token": "id-token",
            "chatgpt_account_id": "acct-cpa",
        })
        response = app.export_cpa(str(row["id"]))
        payload = json.loads(response.body)
        self.assertEqual(payload["type"], "codex")
        self.assertEqual(payload["email"], "cpa@example.com")
        self.assertEqual(payload["account_id"], "acct-cpa")
        self.assertEqual(payload["refresh_token"], "refresh-token")

    def test_password_2fa_import_supports_optional_workspace_id(self):
        from app import _parse_password_2fa

        automatic = _parse_password_2fa(
            "one@example.com----pass----JBSWY3DPEHPK3PXP"
        )[0]
        fixed = _parse_password_2fa(
            "two@example.com----pass----JBSWY3DPEHPK3PXP----workspace-2"
        )[0]
        self.assertNotIn("chatgpt_account_id", automatic)
        self.assertEqual(fixed["chatgpt_account_id"], "workspace-2")

    def test_sub2_export_uses_new_token_identity_and_validates_at_hash(self):
        access = jwt({
            "sub": "new-user",
            "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
            "exp": 1890000000,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "new-workspace",
                "chatgpt_user_id": "new-user",
                "chatgpt_plan_type": "team",
            },
            "https://api.openai.com/profile": {"email": "new@example.com"},
        })
        identity = jwt({
            "at_hash": engine._oidc_at_hash(access),
            "aud": [engine.CODEX_CLIENT_ID],
        })
        row = db.upsert_account({
            "email": "old@example.com",
            "access_token": access,
            "id_token": identity,
            "refresh_token": "rt",
            "chatgpt_account_id": "old-workspace",
            "client_id": "old-client",
        })
        document = app._sub2_account(db.get_account(row["id"]))
        credentials = document["credentials"]
        self.assertEqual(credentials["email"], "new@example.com")
        self.assertEqual(credentials["chatgpt_account_id"], "new-workspace")
        self.assertEqual(credentials["client_id"], engine.CODEX_CLIENT_ID)
        self.assertEqual(
            credentials["device_id"],
            str(uuid.uuid5(uuid.NAMESPACE_DNS, "standalone-401-relogin:new-workspace")),
        )

    def test_sub2_export_rejects_mismatched_id_token(self):
        access = jwt({"client_id": engine.CODEX_CLIENT_ID})
        identity = jwt({"at_hash": "belongs-to-another-access-token"})
        row = db.upsert_account({
            "email": "bad@example.com",
            "access_token": access,
            "id_token": identity,
        })
        with self.assertRaisesRegex(ValueError, "at_hash"):
            app._sub2_account(db.get_account(row["id"]))

    def test_relogin_keeps_codex_token_family_and_device_id(self):
        access = jwt({
            "client_id": engine.CODEX_CLIENT_ID,
            "https://api.openai.com/auth": {"chatgpt_account_id": "workspace-new"},
            "https://api.openai.com/profile": {"email": "fresh@example.com"},
        })
        identity = jwt({"at_hash": engine._oidc_at_hash(access), "aud": [engine.CODEX_CLIENT_ID]})

        class Result:
            email = "fresh@example.com"
            password = "pass"
            totp_secret = "JBSWY3DPEHPK3PXP"
            device_id = "device-new"

            def to_dict(self):
                return {
                    "email": self.email,
                    "password": self.password,
                    "totp_secret": self.totp_secret,
                    "access_token": "web-access",
                    "id_token": "web-id",
                    "refresh_token": "rt-new",
                    "session_token": "st-new",
                    "device_id": self.device_id,
                }

        class Flow:
            def __init__(self, *args, **kwargs):
                self.result = Result()
                self._codex_access_token = access
                self._codex_id_token = identity
                self.session = type("Session", (), {"cookies": {"oai-did": "device-new"}})()

            def run_protocol_login(self, *args, **kwargs):
                return self.result

        with mock.patch.object(engine, "AuthFlow", Flow):
            refreshed = engine.relogin_account({
                "email": "fresh@example.com",
                "password": "pass",
                "totp_secret": "JBSWY3DPEHPK3PXP",
            })
        self.assertEqual(refreshed["access_token"], access)
        self.assertEqual(refreshed["id_token"], identity)
        self.assertEqual(refreshed["device_id"], "device-new")
        self.assertEqual(refreshed["chatgpt_account_id"], "workspace-new")


if __name__ == "__main__":
    unittest.main()
