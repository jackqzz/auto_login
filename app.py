"""Standalone web application for password + 2FA 401 relogin.

Run with ``python start.py``.  It intentionally does not use the parent WebUI
database or its configuration; only the shared AuthFlow implementation is
loaded for the actual OpenAI protocol login.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import sys
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db  # noqa: E402
import engine  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("standalone_401")

app = FastAPI(title="独立 401 重登录工具", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_jobs: dict[str, dict] = {}
_jobs_lock = threading.RLock()
_job_executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix="standalone-401-job")
_workspace_402: set[str] = set()


def _clean_ids(values: Optional[list[Any]]) -> list[int]:
    result: list[int] = []
    seen: set[int] = set()
    for value in values or []:
        try:
            account_id = int(value)
        except (TypeError, ValueError):
            continue
        if account_id not in seen:
            seen.add(account_id)
            result.append(account_id)
    return result


def _job_snapshot(job: dict) -> dict:
    with _jobs_lock:
        result = dict(job)
        result["items"] = [dict(item) for item in job.get("items", [])]
        return result


def _set_job(job_id: str, **values: Any) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job:
            job.update(values)


def _set_item(job_id: str, index: int, **values: Any) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job or index >= len(job.get("items", [])):
            return
        job["items"][index].update(values)
        done = sum(1 for item in job["items"] if item.get("status") in {"success", "failed"})
        job["done"] = done
        job["success"] = sum(1 for item in job["items"] if item.get("status") == "success")
        job["failed"] = sum(1 for item in job["items"] if item.get("status") == "failed")


def _mark_workspace_402(job_id: str, workspace_id: str, message: str) -> None:
    """402 是 workspace 级停用：同步标记同 workspace 的所有账号。"""
    workspace = str(workspace_id or "").strip()
    if not workspace:
        return
    affected = db.mark_workspace_accounts(workspace, status="402", error=message)
    with _jobs_lock:
        _workspace_402.add(workspace)
        job = _jobs.get(job_id)
        if not job:
            return
        affected_set = set(affected)
        for item in job.get("items", []):
            if int(item.get("account_id") or 0) in affected_set:
                item.update({"status": "failed", "error": message})
        job["done"] = sum(1 for item in job["items"] if item.get("status") in {"success", "failed"})
        job["success"] = sum(1 for item in job["items"] if item.get("status") == "success")
        job["failed"] = sum(1 for item in job["items"] if item.get("status") == "failed")


def _new_job(kind: str, account_ids: list[int]) -> dict:
    if not account_ids:
        raise HTTPException(400, "请选择至少一个账号")
    settings = db.get_settings()
    with _jobs_lock:
        active = sum(1 for job in _jobs.values() if job.get("status") in {"queued", "running"})
        # 防止误点造成大量重复请求；不同浏览器共享这个独立工具的队列。
        if active >= 32:
            raise HTTPException(429, "任务队列已满，请稍后重试")
        job_id = uuid.uuid4().hex
        job = {
            "id": job_id,
            "kind": kind,
            "status": "queued",
            "total": len(account_ids),
            "done": 0,
            "success": 0,
            "failed": 0,
            "concurrency": min(settings["concurrency"], len(account_ids)),
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "error": "",
            "items": [
                {"account_id": account_id, "status": "pending", "email": "", "attempts": 0, "error": ""}
                for account_id in account_ids
            ],
        }
        _jobs[job_id] = job
    _job_executor.submit(_run_job, job_id, kind, account_ids)
    return _job_snapshot(job)


def _run_job(job_id: str, kind: str, account_ids: list[int]) -> None:
    settings = db.get_settings()
    _set_job(job_id, status="running", started_at=time.time())

    def one(index: int, account_id: int) -> None:
        account = db.get_account(account_id)
        if not account:
            _set_item(job_id, index, status="failed", error="账号不存在", attempts=1)
            return
        _set_item(job_id, index, status="running", email=account["email"])
        workspace_id = str(account.get("chatgpt_account_id") or "").strip()
        with _jobs_lock:
            workspace_already_402 = bool(workspace_id and workspace_id in _workspace_402)
        if workspace_already_402:
            message = f"workspace {workspace_id} 已因其他账号 HTTP 402 停用"
            db.update_account(account_id, status="402", last_error=message, last_checked_at=time.time())
            _set_item(job_id, index, status="failed", error=message, attempts=0)
            return
        last_error = ""
        previous_proxy = ""
        for attempt in range(1, settings["retry_count"] + 2):
            proxy, proxy_index, lease_count = db.lease_proxy(exclude=previous_proxy)
            _set_item(
                job_id,
                index,
                attempts=attempt,
                proxy=proxy,
                proxy_index=proxy_index,
                proxy_lease_count=lease_count,
            )
            try:
                if kind == "quota":
                    quota = engine.fetch_quota(account, proxy=proxy, timeout=settings["quota_timeout"])
                    with _jobs_lock:
                        workspace_marked = bool(workspace_id and workspace_id in _workspace_402)
                    if workspace_marked:
                        message = f"workspace {workspace_id} 已因其他账号 HTTP 402 停用"
                        db.update_account(account_id, status="402", last_error=message, last_checked_at=time.time())
                        _set_item(job_id, index, status="failed", error=message)
                        return
                    db.update_account(account_id, status="active", quota=quota, last_error="", last_checked_at=time.time())
                    _set_item(job_id, index, status="success", quota=quota, error="")
                    return
                refreshed = engine.relogin_account(account, proxy=proxy, login_timeout=settings["login_timeout"])
                with _jobs_lock:
                    workspace_marked = bool(workspace_id and workspace_id in _workspace_402)
                if workspace_marked:
                    message = f"workspace {workspace_id} 已因其他账号 HTTP 402 停用"
                    db.update_account(account_id, status="402", last_error=message, last_checked_at=time.time())
                    _set_item(job_id, index, status="failed", error=message)
                    return
                db.update_account(
                    account_id,
                    **{key: refreshed.get(key, "") for key in (
                        "access_token", "refresh_token", "id_token", "session_token",
                        "device_id", "chatgpt_account_id", "chatgpt_user_id", "client_id", "organization_id", "plan_type",
                    )},
                    status="revived",
                    last_error="",
                    last_relogin_at=time.time(),
                )
                _set_item(job_id, index, status="success", error="", account=refreshed)
                return
            except engine.AccountDeactivated as exc:
                last_error = str(exc)
                code = int(exc.status_code or 0)
                if code == 402:
                    if workspace_id:
                        _mark_workspace_402(job_id, workspace_id, last_error)
                        logger.warning("workspace=%s 因账号=%s HTTP 402，已批量标记关联账号", workspace_id, account.get("email"))
                    else:
                        db.update_account(account_id, status="402", last_error=last_error, last_checked_at=time.time())
                        _set_item(job_id, index, status="failed", error=last_error)
                else:
                    status = str(code) if code == 403 else "deactivated"
                    db.update_account(account_id, status=status, last_error=last_error, last_checked_at=time.time())
                    _set_item(job_id, index, status="failed", error=last_error)
                return
            except engine.QuotaUnauthorized as exc:
                last_error = str(exc)
                db.update_account(account_id, status="401", last_error=last_error, last_checked_at=time.time())
                if kind == "quota":
                    _set_item(job_id, index, status="failed", error=last_error)
                    return
            except Exception as exc:  # noqa: BLE001
                status_code = engine.http_status_code(exc)
                if status_code in (402, 403):
                    last_error = f"账号停用/不可用 HTTP {status_code}: {str(exc)[:300]}"
                    if status_code == 402:
                        if workspace_id:
                            _mark_workspace_402(job_id, workspace_id, last_error)
                            logger.warning("workspace=%s 因账号=%s HTTP 402，已批量标记关联账号", workspace_id, account.get("email"))
                        else:
                            db.update_account(account_id, status="402", last_error=last_error, last_checked_at=time.time())
                            _set_item(job_id, index, status="failed", error=last_error)
                    else:
                        db.update_account(account_id, status="403", last_error=last_error, last_checked_at=time.time())
                        _set_item(job_id, index, status="failed", error=last_error)
                    return
                last_error = str(exc)[:500]
            previous_proxy = proxy
            if attempt <= settings["retry_count"]:
                time.sleep(min(2.0 * attempt, 5.0))
        db.update_account(account_id, status="error", last_error=last_error, last_checked_at=time.time())
        _set_item(job_id, index, status="failed", error=last_error or "重试耗尽")

    with ThreadPoolExecutor(max_workers=max(1, min(settings["concurrency"], len(account_ids))), thread_name_prefix=f"401-{kind}") as executor:
        futures = [executor.submit(one, index, account_id) for index, account_id in enumerate(account_ids)]
        for future in futures:
            try:
                future.result()
            except Exception as exc:  # pragma: no cover - final safety net
                logger.exception("任务子项异常 job=%s", job_id)
                logger.error("%s", exc)
    snapshot = _jobs.get(job_id, {})
    status = "done" if snapshot.get("failed", 0) == 0 else "done_with_errors"
    _set_job(job_id, status=status, finished_at=time.time())


class ImportRequest(BaseModel):
    text: str = Field("", description="Sub2API JSON 或邮箱----密码----2FA 文本")
    kind: str = Field("sub2api", description="sub2api 或 password_2fa")


class IdsRequest(BaseModel):
    account_ids: list[int] = Field(default_factory=list)


class ProxyImportRequest(BaseModel):
    text: str = ""


class SettingsRequest(BaseModel):
    concurrency: Optional[int] = Field(None, ge=1, le=20)
    quota_timeout: Optional[int] = Field(None, ge=5, le=120)
    login_timeout: Optional[int] = Field(None, ge=30, le=900)
    retry_count: Optional[int] = Field(None, ge=0, le=5)


def _parse_password_2fa(text: str) -> list[dict]:
    rows = []
    errors = []
    for line_number, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----")
        if len(parts) not in (3, 4):
            errors.append(
                f"第 {line_number} 行需要：邮箱----密码----2FA，"
                "或邮箱----密码----2FA----workspace_id"
            )
            continue
        email, password, totp_secret = (part.strip() for part in parts[:3])
        workspace_id = parts[3].strip() if len(parts) == 4 else ""
        if "@" not in email or not password or not totp_secret:
            errors.append(f"第 {line_number} 行邮箱、密码、2FA 均不能为空")
            continue
        if len(parts) == 4 and not workspace_id:
            errors.append(f"第 {line_number} 行 workspace_id 不能为空（不需要指定空间时请删除第四段）")
            continue
        row = {"email": email.lower(), "password": password, "totp_secret": totp_secret}
        if workspace_id:
            row["chatgpt_account_id"] = workspace_id
        rows.append(row)
    if errors:
        raise HTTPException(400, {"message": "密码+2FA 导入格式错误", "errors": errors})
    return rows


def _parse_sub2(text: str) -> list[dict]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Sub2API JSON 解析失败：{exc}") from exc
    if isinstance(payload, dict):
        rows = payload.get("accounts") or payload.get("data") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    if not isinstance(rows, list):
        raise HTTPException(400, "Sub2API JSON 的 accounts 必须是数组")
    return [engine.normalized_account(row) for row in rows if isinstance(row, dict)]


def _account_ids_or_all(account_ids: list[int]) -> list[int]:
    ids = _clean_ids(account_ids)
    if ids:
        return ids
    return [int(row["id"]) for row in db.list_accounts()]


@app.get("/")
def index() -> FileResponse:
    return FileResponse(Path(__file__).resolve().parent / "static" / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "standalone-401-relogin", "version": app.version}


@app.get("/api/accounts")
def accounts() -> dict:
    return {"ok": True, "items": db.list_accounts()}


@app.post("/api/import")
def import_accounts(req: ImportRequest) -> dict:
    kind = (req.kind or "sub2api").strip().lower()
    rows = _parse_password_2fa(req.text) if kind in {"password_2fa", "password+2fa", "pwd2fa"} else _parse_sub2(req.text)
    imported = 0
    for row in rows:
        stored = db.upsert_account(row)
        workspace = str(stored.get("chatgpt_account_id") or row.get("chatgpt_account_id") or "").strip()
        if workspace:
            with _jobs_lock:
                # 重新导入新的凭证是用户明确的恢复动作，允许该 workspace
                # 再次参与任务；否则旧的 402 进程标记会永久拦截重试。
                _workspace_402.discard(workspace)
        imported += 1
    return {"ok": True, "imported": imported, "items": db.list_accounts()}


@app.delete("/api/accounts/{account_id}")
def delete_account(account_id: int) -> dict:
    if not db.delete_account(account_id):
        raise HTTPException(404, "账号不存在")
    return {"ok": True}


@app.post("/api/accounts/clear")
def clear_accounts() -> dict:
    return {"ok": True, "deleted": db.clear_accounts()}


@app.get("/api/proxies")
def proxies() -> dict:
    return {"ok": True, "items": db.list_proxies()}


@app.post("/api/proxies/import")
def import_proxies(req: ProxyImportRequest) -> dict:
    values = [line.strip() for line in str(req.text or "").splitlines() if line.strip() and not line.strip().startswith("#")]
    return {"ok": True, "imported": db.add_proxies(values), "items": db.list_proxies()}


@app.delete("/api/proxies/{proxy_id}")
def delete_proxy(proxy_id: int) -> dict:
    if not db.delete_proxy(proxy_id):
        raise HTTPException(404, "代理不存在")
    return {"ok": True}


@app.post("/api/proxies/clear")
def clear_proxies() -> dict:
    return {"ok": True, "deleted": db.clear_proxies()}


@app.get("/api/settings")
def settings() -> dict:
    return {"ok": True, "settings": db.get_settings()}


@app.post("/api/settings")
def save_settings(req: SettingsRequest) -> dict:
    return {"ok": True, "settings": db.save_settings(req.model_dump(exclude_none=True))}


@app.post("/api/check")
def start_check(req: IdsRequest) -> dict:
    return {"ok": True, "job": _new_job("quota", _account_ids_or_all(req.account_ids))}


@app.post("/api/relogin")
def start_relogin(req: IdsRequest) -> dict:
    return {"ok": True, "job": _new_job("relogin", _account_ids_or_all(req.account_ids))}


@app.get("/api/jobs")
def jobs() -> dict:
    with _jobs_lock:
        values = [_job_snapshot(job) for job in sorted(_jobs.values(), key=lambda item: item["created_at"], reverse=True)]
    return {"ok": True, "items": values[:50]}


@app.get("/api/jobs/{job_id}")
def job(job_id: str) -> dict:
    with _jobs_lock:
        value = _jobs.get(job_id)
    if not value:
        raise HTTPException(404, "任务不存在（服务重启后历史任务不会保留）")
    return {"ok": True, "job": _job_snapshot(value)}


def _sub2_account(account: dict) -> dict:
    token = str(account.get("access_token") or "").strip()
    engine.validate_sub2_token_pair(token, account.get("id_token", ""))
    payload = engine.decode_jwt_payload(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    # AT 中的身份声明优先于导入文件元数据，避免重登录后仍带出旧的
    # client_id / workspace_id，导致 Sub2API 用错 token family。
    account_id = str(auth.get("chatgpt_account_id") or auth.get("account_id") or account.get("chatgpt_account_id") or "").strip()
    user_id = str(auth.get("chatgpt_user_id") or auth.get("user_id") or account.get("chatgpt_user_id") or payload.get("sub") or "").strip()
    email = str(profile.get("email") or account.get("email") or "").strip().lower()
    client_id = str(payload.get("client_id") or engine.CODEX_CLIENT_ID).strip()
    plan_type = str(auth.get("chatgpt_plan_type") or account.get("plan_type") or "team").strip() or "team"
    device_id = str(account.get("device_id") or "").strip() or str(
        uuid.uuid5(uuid.NAMESPACE_DNS, f"standalone-401-relogin:{account_id or email or 'personal'}")
    )
    id_payload = engine.decode_jwt_payload(account.get("id_token", ""))
    id_auth = id_payload.get("https://api.openai.com/auth") or {}
    organization_id = str(
        id_auth.get("organization_id")
        or auth.get("organization_id")
        or auth.get("poid")
        or account.get("organization_id")
        or ""
    ).strip()
    exp = int(payload.get("exp") or 0)
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)) if exp else ""
    exported_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    account_user_id = f"{user_id}__{account_id}" if user_id and account_id else ""
    extra = {
        "email": email,
        "source": "standalone_401_relogin",
        "privacy_mode": "training_off",
        "original_format": "codex-account",
        "openai_oauth_responses_websockets_v2_mode": "off",
        "openai_oauth_responses_websockets_v2_enabled": False,
    }
    live_identity = {
        "plan": plan_type,
        "email": email,
        "user_id": user_id,
        "client_id": client_id,
        "account_id": account_id,
        "plan_source": "oauth_access_token_claim",
        "verified_at": exported_at,
        "email_source": "oauth_access_token_claim",
        "official_plan": plan_type,
        "client_trusted": False,
        "email_verified": True,
        "user_id_source": "oauth_access_token_claim",
        "account_user_id": account_user_id,
        "identity_source": "oauth_access_token_claim",
        "account_id_source": "oauth_access_token_claim",
        "account_user_id_source": "oauth_access_token_claim",
    }
    credentials = {
        "name": profile.get("name") or email,
        "type": "codex",
        "email": email,
        "extra": extra,
        "password": account.get("password", ""),
        "totp_secret": account.get("totp_secret", ""),
        "access_token": token,
        "refresh_token": account.get("refresh_token", ""),
        "id_token": account.get("id_token", ""),
        "session_token": account.get("session_token", ""),
        "client_id": client_id,
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": user_id,
        "plan_type": plan_type,
        "chatgpt_plan_type": plan_type,
        "organization_id": organization_id,
        "workspace_id": account_id,
        "device_id": device_id,
        "oai_device_id": device_id,
        "expired": expires,
        "expires_at": expires,
        "expires_in": max(0, exp - int(time.time())) if exp else 0,
        "disabled": False,
        "email_source": "oauth_access_token_claim",
        "last_refresh": exported_at,
        "live_identity": live_identity,
        "outlook_email": email,
        "identity_source": "oauth_access_token_claim",
        "account_id_source": "oauth_access_token_claim",
        "chatgpt_account_user_id": account_user_id,
    }
    return {
        "name": email,
        "extra": extra,
        "type": "oauth",
        "platform": "openai",
        "priority": 1,
        "plan_type": plan_type,
        "concurrency": 10,
        "credentials": credentials,
        "device_id": device_id,
        "group_ids": [4],
        "expires_at": exp,
        "auto_pause_on_expired": True,
    }


def _cpa_token(account: dict) -> dict:
    """生成 CPA auth-file 格式（与 CPA 面板直接导入兼容）。"""
    token = str(account.get("access_token") or "").strip()
    payload = engine.decode_jwt_payload(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    account_id = str(
        account.get("chatgpt_account_id")
        or auth.get("chatgpt_account_id")
        or auth.get("account_id")
        or ""
    ).strip()
    exp = int(payload.get("exp") or 0)
    expired = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)) if exp else ""
    return {
        "access_token": token,
        "account_id": account_id,
        "disabled": False,
        "email": account.get("email", ""),
        "expired": expired,
        "id_token": account.get("id_token", ""),
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "refresh_token": account.get("refresh_token", ""),
        "type": "codex",
    }


@app.get("/api/export/sub2api")
def export_sub2api(account_ids: str = "") -> Response:
    ids = _clean_ids([value for value in account_ids.split(",") if value.strip()])
    selected = [db.get_account(account_id) for account_id in _account_ids_or_all(ids)]
    rows = [row for row in selected if row]
    document = {
        "type": "sub2api-data",
        "version": 1,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "proxies": [],
        "accounts": [_sub2_account(row) for row in rows],
    }
    body = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sub2api-accounts.json"},
    )


@app.get("/api/export/cpa")
def export_cpa(account_ids: str = "") -> Response:
    """导出 CPA auth-file：单账号 JSON，多账号 ZIP。"""
    ids = _clean_ids([value for value in account_ids.split(",") if value.strip()])
    rows = [db.get_account(account_id) for account_id in _account_ids_or_all(ids)]
    rows = [row for row in rows if row]
    entries = []
    used_names: set[str] = set()
    for index, row in enumerate(rows, 1):
        data = _cpa_token(row)
        base = re.sub(r"[^A-Za-z0-9._@+-]+", "_", str(data.get("email") or f"account-{index}")).strip("._") or f"account-{index}"
        name = f"{base}.json"
        suffix = 2
        while name in used_names:
            name = f"{base}-{suffix}.json"
            suffix += 1
        used_names.add(name)
        entries.append((name, data))
    if len(entries) <= 1:
        data = entries[0][1] if entries else {}
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=cpa-account.json"},
        )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, json.dumps(data, ensure_ascii=False, indent=2))
    return Response(
        content=output.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=cpa-accounts.zip"},
    )


@app.get("/api/export/password-2fa")
def export_password_2fa(account_ids: str = "") -> Response:
    ids = _clean_ids([value for value in account_ids.split(",") if value.strip()])
    rows = [db.get_account(account_id) for account_id in _account_ids_or_all(ids)]
    text = "\n".join(
        f"{row.get('email', '')}----{row.get('password', '')}----{row.get('totp_secret', '')}"
        for row in rows if row
    ) + ("\n" if rows else "")
    return Response(
        content=text.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=accounts-password-2fa.txt"},
    )
