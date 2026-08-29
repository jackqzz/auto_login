# 独立 401 重登录 Web 工具

这是一个与主 WebUI 分离的 401 重登录工具。它有自己的 SQLite 数据库、账号导入、代理池、任务队列和导出功能，不读取 `webui/webui.db`，也不依赖主 WebUI 的登录状态。

实际登录协议复用父项目的 `AuthFlow`，这样 401 重登录和主项目使用同一套已验证的 OpenAI 登录实现；账号和代理数据仍完全存储在本目录 `data/relogin.sqlite3`。

## 启动

在父项目的 Python 环境中运行：

```bash
cd /home/manq_dev/gpt-auto-register/401-relogin-web
/home/manq_dev/gpt-outlook/.venv/bin/python start.py --host 0.0.0.0 --port 8876
```

打开 `http://服务器地址:8876/`。如果单独部署到其他位置，请设置 `PYTHONPATH` 指向父项目根目录，以便加载 `auth_flow.py`、`config.py` 和邮箱 provider 基础类。

## 导入格式

默认导入格式是 Sub2API JSON（支持 `accounts[].credentials` 结构）。工具会从 `credentials` 中读取邮箱、密码、2FA、AT/RT/ID 和 workspace/account id。

也支持直接导入密码 + 2FA 文本，每行必须是：

```text
email@example.com----OpenAI密码----TOTP_SECRET
```

空行和 `#` 开头的注释行会忽略。导入同一个邮箱会合并非空凭证，不会无故覆盖已有 AT/RT/ID。

## 功能

- 独立账号列表和选择；
- 独立代理池，按租用次数最少选择，失败重试会切换代理；
- 额度查询，401/停用状态单独标记；
- 密码 + 2FA 批量重登录，后台任务滚动显示进度；
- 导出 CPA JSON/ZIP、Sub2API JSON 或 `邮箱----密码----2FA` 文本；
- 并发、超时、重试次数均可在页面配置。

HTTP 402/403 会直接按停用处理。HTTP 402 表示 workspace 级停用：工具会把本地账号库中相同 `chatgpt_account_id` 的所有账号一起标记为 402，并在当前任务中一并计为失败。重新导入该 workspace 的新凭证后，才会解除本进程中的 402 拦截标记。

账号凭证和代理都属于敏感数据，请只在可信网络中运行，必要时在反向代理层增加访问控制。
