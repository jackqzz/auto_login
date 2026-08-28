"""独立 401 重登录工具使用的 OpenAI 协议引擎。

这个文件只依赖主项目中稳定的 AuthFlow / Config / HTTP 会话实现，不依赖
主 WebUI 的数据库、设置或任务队列。账号、代理和任务状态全部由本工具自己管理。
"""
from __future__ import annotations

import base64
import json
import logging
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

# The standalone repository lives inside the parent project. Keep this import
# explicit and documented so the tool can also be copied elsewhere with
# ``PYTHONPATH=/path/to/gpt-auto-register``.
PARENT_ROOT = Path(__file__).resolve().parents[1]
if str(PARENT_ROOT) not in sys.path:
    sys.path.insert(0, str(PARENT_ROOT))

from auth_flow import AuthFlow
from config import Config
from http_client import create_http_session
from mail_providers.base import MailProvider

BASE = "https://chatgpt.com"
logger = logging.getLogger("relogin_engine")


def _text(value: Any) -> str:
    return str(value or "").strip()


def _object(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _field(sources: list[dict], *names: str) -> Any:
    for source in sources:
        for name in names:
            value = source.get(name)
            if value not in (None, ""):
                return value
    return ""


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = _text(token).split(".")
        if len(parts) < 2:
            return {}
        raw = parts[1].replace("-", "+").replace("_", "/")
        raw += "=" * ((4 - len(raw) % 4) % 4)
        value = json.loads(base64.b64decode(raw).decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _auth(token: str) -> dict:
    payload = decode_jwt_payload(token)
    value = payload.get("https://api.openai.com/auth")
    return value if isinstance(value, dict) else {}


def _profile(token: str) -> dict:
    payload = decode_jwt_payload(token)
    value = payload.get("https://api.openai.com/profile")
    return value if isinstance(value, dict) else {}


def normalized_account(raw: dict) -> dict:
    """兼容 Sub2API / CPA / 旧字段，归一化为工具内部账号对象。"""
    raw = _object(raw)
    credentials = _object(raw.get("credentials"))
    data = _object(raw.get("data"))
    extra = _object(raw.get("extra"))
    sources = [credentials, data, raw, extra]
    access_token = _text(_field(sources, "access_token", "accessToken", "access-token", "token"))
    auth = _auth(access_token)
    profile = _profile(access_token)
    email = _text(
        _field(sources, "email", "mail", "username", "name") or profile.get("email")
    ).lower()
    account_id = _text(
        _field(sources, "chatgpt_account_id", "chatgptAccountId", "workspace_id", "workspaceId")
        or auth.get("chatgpt_account_id")
        or auth.get("account_id")
        or _field(sources, "account_id", "accountId")
    )
    user_id = _text(
        _field(sources, "chatgpt_user_id", "chatgptUserId", "user_id", "userId")
        or auth.get("chatgpt_user_id")
        or auth.get("user_id")
    )
    return {
        "email": email,
        "password": _text(_field(sources, "password", "passwd")),
        "totp_secret": _text(
            _field(sources, "totp_secret", "totpSecret", "two_factor_secret", "twoFactorSecret", "2fa")
        ),
        "access_token": access_token,
        "refresh_token": _text(_field(sources, "refresh_token", "refreshToken")),
        "id_token": _text(_field(sources, "id_token", "idToken")),
        "session_token": _text(_field(sources, "session_token", "sessionToken")),
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": user_id,
        "client_id": _text(_field(sources, "client_id", "clientId")),
        "plan_type": _text(_field(sources, "plan_type", "planType") or auth.get("chatgpt_plan_type") or "team"),
        "organization_id": _text(_field(sources, "organization_id", "organizationId") or auth.get("organization_id")),
    }


def account_headers(account: dict) -> dict:
    cred = normalized_account(account)
    token = cred["access_token"]
    account_id = cred["chatgpt_account_id"]
    email = cred["email"]
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": BASE,
        "Referer": f"{BASE}/",
        "User-Agent": "codex-cli",
        "oai-device-id": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"standalone-401-relogin:{account_id or email or 'personal'}")),
    }
    if account_id:
        headers["chatgpt-account-id"] = account_id
        headers["ChatGPT-Account-Id"] = account_id
    return headers


class QuotaUnauthorized(RuntimeError):
    """额度接口返回 401，表示需要重登录。"""


class AccountDeactivated(RuntimeError):
    """账号被停用或永久失效。"""


def _looks_deactivated(body: str) -> bool:
    lower = str(body or "").lower()
    return any(marker in lower for marker in (
        "account deactivated", "account has been deactivated", "account disabled",
        "user_deactivated", "user disabled", "account is not active",
    ))


def fetch_quota(account: dict, *, proxy: str = "", timeout: int = 30) -> dict:
    cred = normalized_account(account)
    if not cred["access_token"]:
        raise ValueError("缺少 access_token")
    session = create_http_session(proxy=proxy or None)
    response = session.get(
        f"{BASE}/backend-api/wham/usage",
        headers=account_headers(cred),
        timeout=max(5, int(timeout or 30)),
    )
    if response.status_code >= 300:
        body = _text(getattr(response, "text", ""))[:1000]
        if response.status_code == 401:
            raise QuotaUnauthorized("额度查询失败 HTTP 401")
        if response.status_code == 403 or _looks_deactivated(body):
            raise AccountDeactivated(f"账号停用/不可用 HTTP {response.status_code}")
        raise RuntimeError(f"额度查询失败 HTTP {response.status_code}: {body[:300]}")
    payload = response.json()
    rate = payload.get("rate_limit") or {}
    credits = payload.get("credits") or {}

    def window(key: str) -> dict:
        value = rate.get(key) or {}
        return {
            "used_percent": value.get("used_percent"),
            "window_seconds": value.get("limit_window_seconds"),
            "reset_at": value.get("reset_at"),
        }

    return {
        "plan_type": payload.get("plan_type") or cred.get("plan_type") or "",
        "credits_balance": credits.get("balance"),
        "allowed": rate.get("allowed"),
        "primary": window("primary_window"),
        "secondary": window("secondary_window"),
        "updated_at": time.time(),
    }


class _NoOtpMailProvider(MailProvider):
    kind = "standalone_401_relogin"
    display_name = "独立401重登（密码+2FA）"
    pooled = False
    ephemeral = False
    accepts_existing_account = True

    def __init__(self, email: str):
        self.email = _text(email).lower()

    def create_mailbox(self) -> str:
        return self.email

    def wait_for_otp(self, email_addr: str, timeout: int = 120, issued_after=None) -> str:
        raise RuntimeError("独立 401 重登录只支持密码 + 2FA，不会请求邮箱 OTP")


def relogin_account(account: dict, *, proxy: str = "", login_timeout: int = 180, on_proxy_switch=None) -> dict:
    """使用导入的密码 + TOTP 完成协议登录并返回新凭证。"""
    cred = normalized_account(account)
    email = cred["email"]
    password = cred["password"]
    totp_secret = cred["totp_secret"]
    workspace_id = cred["chatgpt_account_id"]
    if not email:
        raise ValueError("缺少 email")
    if not password:
        raise ValueError("缺少 password，无法执行密码登录")
    if not totp_secret:
        raise ValueError("缺少 totp_secret，无法执行 2FA 登录")

    cfg = Config(proxy=(proxy or "").strip() or None)

    def account_callback(_email: str) -> dict:
        return {"password": password, "totp_secret": totp_secret}

    flow = AuthFlow(
        cfg,
        env_overrides={
            "WEBUI_ALLOW_LOGIN": "1",
            "LOCALAUTH_EXISTING_LOGIN_USE_LOGIN_HINT": "1",
            "OTP_TIMEOUT": str(max(10, int(login_timeout or 180))),
            "OAUTH_CODEX_RT_EXCHANGE": "1",
            "OAUTH_CODEX_RT_BEFORE_CALLBACK": "1",
            "OAUTH_TOKEN_EXCHANGE_FROM_CALLBACK": "0",
        },
        account_callback=account_callback,
        on_proxy_switch=on_proxy_switch,
        workspace_id=workspace_id,
        personal_only=False,
    )
    flow.result.totp_secret = totp_secret
    result = flow.run_protocol_login(_NoOtpMailProvider(email), email, password=password)
    data = result.to_dict()
    data.update({"email": email, "password": password, "totp_secret": totp_secret})
    refreshed = normalized_account({**cred, **data})
    refreshed_workspace = refreshed.get("chatgpt_account_id") or workspace_id
    if workspace_id and refreshed_workspace != workspace_id:
        raise RuntimeError(f"重登后 workspace 不匹配: {refreshed_workspace} != {workspace_id}")
    return refreshed
