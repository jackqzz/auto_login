# 独立 401 重登录 Web 工具

这是一个与主 WebUI 分离的 401 重登录工具。它有自己的 SQLite 数据库、账号导入、代理池、任务队列和导出功能，不读取 `webui/webui.db`，也不依赖主 WebUI 的登录状态。

实际登录协议复用父项目的 `AuthFlow`，这样 401 重登录和主项目使用同一套已验证的 OpenAI 登录实现；账号和代理数据仍完全存储在本目录 `data/relogin.sqlite3`。

## 环境准备

独立仓库自己管理 Web 工具代码和数据，但登录引擎依赖父项目中的以下源码：
`auth_flow.py`、`config.py`、`fingerprint.py`、`http_client.py` 和 `mail_providers/`。
因此需要先准备一份父项目代码。独立工具不会读取父项目的 `webui/webui.db`。

从 GitHub 获取独立工具：

```bash
git clone git@github.com:jackqzz/auto_login.git /opt/auto_login
```

下面示例假设父项目位于 `/home/manq_dev/gpt-auto-register`，独立工具位于其下的 `401-relogin-web`；如果路径不同，请相应替换。

### 1. 准备 Python 3.12 环境

推荐沿用父项目已经验证过的虚拟环境：

```bash
cd /home/manq_dev/gpt-auto-register
/home/manq_dev/gpt-outlook/.venv/bin/python --version
/home/manq_dev/gpt-outlook/.venv/bin/python -m pip install -r requirements.txt
```

如果是全新机器，也可以创建自己的 Python 3.12 虚拟环境：

```bash
python3.12 -m venv /opt/auto-login-venv
source /opt/auto-login-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r /path/to/gpt-auto-register/requirements.txt
```

### 2. 安装独立工具依赖

```bash
cd /home/manq_dev/gpt-auto-register/401-relogin-web
/home/manq_dev/gpt-outlook/.venv/bin/python -m pip install -r requirements.txt
```

如果独立仓库被克隆到父项目之外，需要把父项目根目录加入 `PYTHONPATH`：

```bash
export PYTHONPATH=/path/to/gpt-auto-register${PYTHONPATH:+:$PYTHONPATH}
```

### 3. 检查导入环境

```bash
cd /home/manq_dev/gpt-auto-register/401-relogin-web
/home/manq_dev/gpt-outlook/.venv/bin/python - <<'PY'
import auth_flow, config, fingerprint, http_client
from mail_providers.base import MailProvider
print("AuthFlow environment OK")
PY
```

看到 `AuthFlow environment OK` 后再启动服务。

## 启动

在父项目的 Python 环境中运行：

```bash
cd /home/manq_dev/gpt-auto-register/401-relogin-web
/home/manq_dev/gpt-outlook/.venv/bin/python start.py --host 0.0.0.0 --port 8876
```

打开 `http://服务器地址:8876/`。如果单独部署到其他位置，请设置 `PYTHONPATH` 指向父项目根目录，以便加载 `auth_flow.py`、`config.py` 和邮箱 provider 基础类。

### 后台运行（tmux）

```bash
tmux new-session -d -s 401-relogin \
  -c /home/manq_dev/gpt-auto-register/401-relogin-web \
  "/home/manq_dev/gpt-outlook/.venv/bin/python start.py --host 0.0.0.0 --port 8876"
tmux attach -t 401-relogin
```

查看服务日志：

```bash
tmux capture-pane -p -t 401-relogin -S -200
```

健康检查：

```bash
curl -fsS http://127.0.0.1:8876/api/health
```

## 导入格式

默认导入格式是 Sub2API JSON（支持 `accounts[].credentials` 结构）。工具会从 `credentials` 中读取邮箱、密码、2FA、AT/RT/ID 和 workspace/account id。

也支持直接导入密码 + 2FA 文本。默认三段格式为：

```text
email@example.com----OpenAI密码----TOTP_SECRET
```

三段格式不会指定空间：登录时使用 OpenAI 返回的空间列表中的第一个空间。
如果账号属于多个空间、需要固定目标，请使用扩展的四段格式：

```text
email@example.com----OpenAI密码----TOTP_SECRET----workspace_id
```

四段格式会强制调用指定 Workspace ID，不会随机选择。空行和 `#` 开头的注释行会忽略。导入同一个邮箱会合并非空凭证，不会无故覆盖已有 AT/RT/ID；已保存的 Workspace ID 也不会被一次三段格式的重复导入清空。

## 功能

- 独立账号列表和选择；
- 独立代理池，按租用次数最少选择，失败重试会切换代理；
- 额度查询，401/停用状态单独标记；
- 密码 + 2FA 批量重登录，后台任务滚动显示进度；
- 导出 CPA JSON/ZIP、Sub2API JSON 或 `邮箱----密码----2FA` 文本；
- 并发、超时、重试次数均可在页面配置。

HTTP 402/403 会直接按停用处理。HTTP 402 表示 workspace 级停用：工具会把本地账号库中相同 `chatgpt_account_id` 的所有账号一起标记为 402，并在当前任务中一并计为失败。重新导入该 workspace 的新凭证后，才会解除本进程中的 402 拦截标记。

Sub2API 导出会以重登录后新 AT 的 JWT 声明为身份来源，使用同一组 Codex `access_token`、`id_token`、`refresh_token`，校验 `id_token.at_hash`，并保存本次登录的 `device_id`。导入文件中的旧 `client_id`、邮箱或 Workspace 元数据不会覆盖新 AT 的声明，避免下载后导入 Sub2API 返回 401。

账号凭证和代理都属于敏感数据，请只在可信网络中运行，必要时在反向代理层增加访问控制。
