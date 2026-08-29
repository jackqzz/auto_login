"""独立 401 重登录工具的 SQLite 存储。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent / "data" / "relogin.sqlite3"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.RLock()


def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH), timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password TEXT NOT NULL DEFAULT '',
                totp_secret TEXT NOT NULL DEFAULT '',
                access_token TEXT NOT NULL DEFAULT '',
                refresh_token TEXT NOT NULL DEFAULT '',
                id_token TEXT NOT NULL DEFAULT '',
                session_token TEXT NOT NULL DEFAULT '',
                chatgpt_account_id TEXT NOT NULL DEFAULT '',
                chatgpt_user_id TEXT NOT NULL DEFAULT '',
                client_id TEXT NOT NULL DEFAULT '',
                organization_id TEXT NOT NULL DEFAULT '',
                plan_type TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'imported',
                quota_json TEXT NOT NULL DEFAULT '{}',
                last_error TEXT NOT NULL DEFAULT '',
                last_checked_at REAL,
                last_relogin_at REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy TEXT NOT NULL COLLATE NOCASE UNIQUE,
                lease_count INTEGER NOT NULL DEFAULT 0,
                last_used_at REAL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO settings(key, value) VALUES
                ('concurrency', '4'),
                ('quota_timeout', '30'),
                ('login_timeout', '180'),
                ('retry_count', '1');
            """
        )
        con.commit()
        con.close()


def _row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    out = dict(row)
    try:
        out["quota"] = json.loads(out.pop("quota_json") or "{}")
    except Exception:
        out["quota"] = {}
        out.pop("quota_json", None)
    return out


def list_accounts() -> list[dict]:
    with _lock:
        con = _conn()
        rows = [_row(row) for row in con.execute("SELECT * FROM accounts ORDER BY id")]
        con.close()
    return [row for row in rows if row]


def get_account(account_id: int) -> dict | None:
    with _lock:
        con = _conn()
        row = _row(con.execute("SELECT * FROM accounts WHERE id=?", (int(account_id),)).fetchone())
        con.close()
    return row


def get_account_by_email(email: str) -> dict | None:
    with _lock:
        con = _conn()
        row = _row(con.execute("SELECT * FROM accounts WHERE email=?", (str(email).strip().lower(),)).fetchone())
        con.close()
    return row


def upsert_account(data: dict) -> dict:
    email = str(data.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise ValueError("账号缺少有效 email")
    now = time.time()
    fields = {
        key: str(data.get(key) or "").strip()
        for key in (
            "password", "totp_secret", "access_token", "refresh_token", "id_token",
            "session_token", "chatgpt_account_id", "chatgpt_user_id", "client_id",
            "organization_id", "plan_type",
        )
    }
    status = str(data.get("status") or "imported").strip()
    quota = data.get("quota") if isinstance(data.get("quota"), dict) else {}
    with _lock:
        con = _conn()
        con.execute(
            """
            INSERT INTO accounts(email,password,totp_secret,access_token,refresh_token,id_token,
              session_token,chatgpt_account_id,chatgpt_user_id,client_id,organization_id,plan_type,
              status,quota_json,last_error,last_checked_at,last_relogin_at,created_at,updated_at)
            VALUES (:email,:password,:totp_secret,:access_token,:refresh_token,:id_token,
              :session_token,:chatgpt_account_id,:chatgpt_user_id,:client_id,:organization_id,:plan_type,
              :status,:quota_json,'',NULL,NULL,:now,:now)
            ON CONFLICT(email) DO UPDATE SET
              password=CASE WHEN excluded.password<>'' THEN excluded.password ELSE accounts.password END,
              totp_secret=CASE WHEN excluded.totp_secret<>'' THEN excluded.totp_secret ELSE accounts.totp_secret END,
              access_token=CASE WHEN excluded.access_token<>'' THEN excluded.access_token ELSE accounts.access_token END,
              refresh_token=CASE WHEN excluded.refresh_token<>'' THEN excluded.refresh_token ELSE accounts.refresh_token END,
              id_token=CASE WHEN excluded.id_token<>'' THEN excluded.id_token ELSE accounts.id_token END,
              session_token=CASE WHEN excluded.session_token<>'' THEN excluded.session_token ELSE accounts.session_token END,
              chatgpt_account_id=CASE WHEN excluded.chatgpt_account_id<>'' THEN excluded.chatgpt_account_id ELSE accounts.chatgpt_account_id END,
              chatgpt_user_id=CASE WHEN excluded.chatgpt_user_id<>'' THEN excluded.chatgpt_user_id ELSE accounts.chatgpt_user_id END,
              client_id=CASE WHEN excluded.client_id<>'' THEN excluded.client_id ELSE accounts.client_id END,
              organization_id=CASE WHEN excluded.organization_id<>'' THEN excluded.organization_id ELSE accounts.organization_id END,
              plan_type=CASE WHEN excluded.plan_type<>'' THEN excluded.plan_type ELSE accounts.plan_type END,
              status=CASE WHEN excluded.access_token<>'' THEN 'imported' ELSE accounts.status END,
              updated_at=:now
            """,
            {**fields, "email": email, "status": status, "quota_json": json.dumps(quota), "now": now},
        )
        con.commit()
        row = _row(con.execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone())
        con.close()
    return row or {}


def update_account(account_id: int, **values: Any) -> dict | None:
    allowed = {
        "password", "totp_secret", "access_token", "refresh_token", "id_token", "session_token",
        "chatgpt_account_id", "chatgpt_user_id", "client_id", "organization_id", "plan_type",
        "status", "last_error", "last_checked_at", "last_relogin_at",
    }
    fields: dict[str, Any] = {}
    for key, value in values.items():
        if key not in allowed:
            continue
        fields[key] = value if isinstance(value, (int, float)) else str(value or "").strip()
    if "quota" in values:
        fields["quota_json"] = json.dumps(values["quota"] if isinstance(values["quota"], dict) else {})
    if not fields:
        return get_account(account_id)
    fields["updated_at"] = time.time()
    assignments = ",".join(f"{key}=?" for key in fields)
    with _lock:
        con = _conn()
        con.execute(f"UPDATE accounts SET {assignments} WHERE id=?", (*fields.values(), int(account_id)))
        con.commit()
        row = _row(con.execute("SELECT * FROM accounts WHERE id=?", (int(account_id),)).fetchone())
        con.close()
    return row


def mark_workspace_accounts(workspace_id: str, *, status: str, error: str) -> list[int]:
    """将同一 workspace/account id 的账号原子标记为停用状态。"""
    workspace = str(workspace_id or "").strip()
    if not workspace:
        return []
    now = time.time()
    with _lock:
        con = _conn()
        rows = con.execute(
            "SELECT id FROM accounts WHERE chatgpt_account_id=?",
            (workspace,),
        ).fetchall()
        con.execute(
            "UPDATE accounts SET status=?,last_error=?,last_checked_at=?,updated_at=? WHERE chatgpt_account_id=?",
            (str(status), str(error or "")[:500], now, now, workspace),
        )
        con.commit()
        con.close()
    return [int(row[0]) for row in rows]


def delete_account(account_id: int) -> bool:
    with _lock:
        con = _conn()
        result = con.execute("DELETE FROM accounts WHERE id=?", (int(account_id),))
        con.commit()
        con.close()
    return result.rowcount > 0


def clear_accounts() -> int:
    with _lock:
        con = _conn()
        result = con.execute("DELETE FROM accounts")
        con.commit()
        con.close()
    return result.rowcount


def list_proxies() -> list[dict]:
    with _lock:
        con = _conn()
        rows = [dict(row) for row in con.execute("SELECT * FROM proxies ORDER BY id")]
        con.close()
    return rows


def add_proxies(values: list[str]) -> int:
    cleaned = list(dict.fromkeys(str(value or "").strip() for value in values if str(value or "").strip()))
    if not cleaned:
        return 0
    now = time.time()
    with _lock:
        con = _conn()
        before = con.total_changes
        con.executemany(
            "INSERT OR IGNORE INTO proxies(proxy,lease_count,last_used_at,created_at) VALUES (?,0,NULL,?)",
            [(value, now) for value in cleaned],
        )
        count = con.total_changes - before
        con.commit()
        con.close()
    return count


def clear_proxies() -> int:
    with _lock:
        con = _conn()
        result = con.execute("DELETE FROM proxies")
        con.commit()
        con.close()
    return result.rowcount


def delete_proxy(proxy_id: int) -> bool:
    with _lock:
        con = _conn()
        result = con.execute("DELETE FROM proxies WHERE id=?", (int(proxy_id),))
        con.commit()
        con.close()
    return result.rowcount > 0


def lease_proxy(exclude: str = "") -> tuple[str, int, int]:
    """原子地领取当前计数最小代理，并优先避开上一条失败代理。"""
    with _lock:
        con = _conn()
        con.execute("BEGIN IMMEDIATE")
        rows = con.execute("SELECT id,proxy,lease_count FROM proxies ORDER BY lease_count,id").fetchall()
        if not rows:
            con.rollback()
            con.close()
            return "", -1, 0
        candidates = [row for row in rows if row[1] != str(exclude or "").strip()] or list(rows)
        minimum = min(int(row[2]) for row in candidates)
        chosen = next(row for row in candidates if int(row[2]) == minimum)
        new_count = int(chosen[2]) + 1
        con.execute("UPDATE proxies SET lease_count=?,last_used_at=? WHERE id=?", (new_count, time.time(), chosen[0]))
        con.commit()
        con.close()
    index = next((index for index, row in enumerate(rows) if row[0] == chosen[0]), -1)
    return str(chosen[1]), index, new_count


def get_setting(key: str, default: str = "") -> str:
    with _lock:
        con = _conn()
        row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        con.close()
    return str(row[0]) if row else default


def save_settings(values: dict) -> dict:
    allowed = {"concurrency", "quota_timeout", "login_timeout", "retry_count"}
    with _lock:
        con = _conn()
        for key, value in values.items():
            if key in allowed:
                con.execute(
                    "INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, str(value)),
                )
        con.commit()
        con.close()
    return get_settings()


def get_settings() -> dict:
    return {
        "concurrency": max(1, min(20, int(get_setting("concurrency", "4") or 4))),
        "quota_timeout": max(5, min(120, int(get_setting("quota_timeout", "30") or 30))),
        "login_timeout": max(30, min(900, int(get_setting("login_timeout", "180") or 180))),
        "retry_count": max(0, min(5, int(get_setting("retry_count", "1") or 1))),
    }


init_db()
