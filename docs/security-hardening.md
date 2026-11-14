# 安全加固版使用说明（v2）

安全入口是**新增的可选入口**，不覆盖原始 `server.py` / `console/app.py`。MCP 客户端应改为启动 `secure_server.py`；浏览器控制台应使用 `python secure_console.py`。请先在隔离实验环境验证厂商命令与交互流程，再连接生产设备。

> 前提：不经过这两个入口就等于没有任何保护。原始入口按设计保留，可直接运行，不做拦截。

## v2 修了什么

| v1 问题 | v2 处理 |
|---|---|
| `secure_console.py` 用 `@app.middleware("http")`，该方法在 Starlette 1.x 已移除 → 装最新依赖直接启动失败 | 去掉该装饰器，令牌校验下沉到端点包装函数 |
| 用 `route.endpoint = _guarded_xxx` 打补丁；但 `Route.__init__` 里已 `self.app = request_response(endpoint)` 绑定，运行期分发**完全绕过**守卫，加固形同虚设 | 改为**重建路由表**，用包装后的处理函数构造新 `Route` |
| `approval="CONFIRM <session_id>"` 被报错信息原样回显，Agent 一次往返即可自我批准 | 审批串必须包含 `NETCLI_APPROVAL_SECRET`；报错**不复述**期望值；未配置审批码时直接禁用写操作 |
| `local-user x password irreversible-cipher $1c$...` 把 `irreversible-cipher` 当密码脱敏，真哈希明文外泄 | 关键词表补 `irreversible-cipher`；另加 `$1c$` / `$9$` / `%^%#` 裸哈希兜底 |
| `snmp-agent community read public` 把 `read` 脱了、社区串留下 | SNMP 规则前置并保留权限位，只脱真正的串 |
| `radius-server shared-key cipher xxx` 完全未脱敏 | 关键词表补 `shared-key` |
| `display interface brief`、`display this interface` 被判为写操作；`display x \| include y` 因 `\|` 直接拒 | 只读判定改**前缀白名单**，管道放行 `include/exclude/begin/section/grep` 过滤段 |
| 设了 `NETCLI_API_TOKEN` 控制台立刻全 401（前端不带 token） | 页面下发 HttpOnly Cookie，EventSource 与 fetch 自动携带；另支持 header 与 `?token=` |
| README 完全没提安全入口 | 补目录树与安全章节 |

## 安全策略

| 环境变量 | 默认值 | 作用 |
|---|---|---|
| `NETCLI_COMMAND_POLICY` | `guarded` | `guarded` 放行查询类命令，写操作须审批；`readonly` 拒绝一切写操作；`unrestricted` 不拦截（不建议） |
| `NETCLI_APPROVAL_MODE` | `secret` | `secret` 用审批码（推荐）；`echo` 复刻 v1 行为，**Agent 可自行构造**，仅实验；`off` 不审批 |
| `NETCLI_APPROVAL_SECRET` | 未设置 | 审批码，只在服务端进程环境里。**未设置时 `guarded` 下写操作一律拒绝**（fail-closed） |
| `NETCLI_ALLOWED_HOSTS` | 未设置 | 逗号分隔的主机/IP/CIDR 白名单；设置后拒绝不匹配的 Telnet/SSH 目标。主机名只做精确匹配，不做 DNS 解析 |
| `NETCLI_ALLOWED_SERIAL_PORTS` | 未设置 | 逗号分隔串口白名单，例如 `COM3,/dev/ttyUSB0` |
| `NETCLI_API_TOKEN` | 未设置 | 设置后所有 `/api/*` 必须带令牌：`Authorization: Bearer`、`X-NetCLI-Token`、页面下发的 HttpOnly Cookie，或 `?token=` |
| `NETCLI_MAX_OUTPUT_CHARS` | `65536` | 返回文本的截断上限 |
| `NETCLI_MAX_WAIT_MS` | `120000` | 单命令最大等待时间 |
| `NETCLI_AUDIT_LOG` | 未设置 | JSONL 审计日志路径；建议指向权限受限的本地目录 |

只读白名单前缀：`display` `show` `ping` `ping6` `tracert` `traceroute` `terminal length` `screen-length` `dir` `more` `help` `?` `quit` `exit` `return` `end`。管道后仅允许 `include` `exclude` `begin` `section` `grep`。其余语法一律按写操作处理，需审批。

## 关于审批码

审批码是**给人和 Agent 之间的一个带外凭证**，不是加密机制：

- 服务端只认 `CONFIRM <session_id> <审批码>`；界面上也可以只填审批码，服务端会自动补前缀。
- 审批码存在启动进程的环境变量里，Agent 通过 MCP/HTTP 拿不到；v1 那种"报错里把答案念出来"的写法已删除。
- 因此 `NETCLI_APPROVAL_SECRET` 一旦泄漏（写进 prompt、日志、仓库、`.env` 提交），这套机制就退化成 `echo`。轮换方式是改环境变量并重启。

残余风险（务必知悉）：任何能以同一用户身份读该进程环境或读到审批码的本地程序，都能绕过。**真正的边界是设备侧 RBAC/AAA 与只读账号**，不是这一层。生产核心设备建议给自动化单独建只读账号，写操作走人工。

## 启动

MCP 客户端（`mcp-config.example.json`）：

```json
{
  "mcpServers": {
    "net-cli-mcp": {
      "command": "python",
      "args": ["/绝对路径/AI-net-cli-mcp/secure_server.py"],
      "env": {
        "NETCLI_COMMAND_POLICY": "guarded",
        "NETCLI_APPROVAL_SECRET": "换成你自己的审批码",
        "NETCLI_ALLOWED_HOSTS": "192.168.10.0/24",
        "NETCLI_AUDIT_LOG": "/绝对路径/audit.jsonl"
      }
    }
  }
}
```

控制台：

```bash
python secure_console.py
```

Windows 也可以双击 `console/启动安全控制台.bat`：它会先问你要审批码（直接回车 = 以只读模式启动），再停掉占用 8199 的旧实例并拉起安全入口。审批码只存在于该进程环境里，不落盘。

Linux/macOS：

```bash
export NETCLI_COMMAND_POLICY=guarded
export NETCLI_APPROVAL_SECRET='换成你自己的审批码'
export NETCLI_ALLOWED_HOSTS="192.168.10.0/24,127.0.0.1"
export NETCLI_AUDIT_LOG="$HOME/.local/state/net-cli-mcp/audit.jsonl"
export NETCLI_API_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python secure_console.py
```

Windows PowerShell：

```powershell
$env:NETCLI_COMMAND_POLICY = "guarded"
$env:NETCLI_APPROVAL_SECRET = "换成你自己的审批码"
$env:NETCLI_ALLOWED_HOSTS = "192.168.10.0/24"
$env:NETCLI_AUDIT_LOG = "$env:LOCALAPPDATA\net-cli-mcp\audit.jsonl"
python secure_console.py
```

启动时会打印生效策略，便于确认加固是否真的挂上：

```
[net-cli-mcp] policy=guarded approval=secret secret=set token=unset
```

## 自测

```bash
python selftest.py
```

覆盖：命令分类（写/读/管道/多命令）、审批码正反例、脱敏（`irreversible-cipher`、SNMP、shared-key、裸哈希）、令牌与白名单拦截、`/api/exec` 端到端 428 → 放行、SSE 路由存在性。全部用例使用 Starlette TestClient，**不连接任何设备**。

## 当前边界

- 只读识别是启发式规则，厂商扩展命令可能被判为写操作（需要审批），这是刻意选择：宁可多问一次，不可放任。发现正常查询被拦时，改 `security.py` 的 `_READ_ONLY_VERB` 并按需回归 `selftest.py`。
- 脱敏是正则，不保证覆盖所有厂商/版本格式。控制台 `console/logs/*.jsonl` 仍会落原始回显（仅经 `push` 脱敏），请限制目录权限并定期清理。
- 输出截断只限制返回内容与广播事件大小，不是设备侧分页/执行取消机制。
- API 令牌用于把"能访问 8199 的进程"收敛成"持有令牌的调用方"，但同机同用户的进程仍可能读到令牌文件；它替代不了把控制台放在带外管理网。
