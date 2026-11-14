"""Hardened local-console entrypoint (v2). Run with: python secure_console.py

与 v1 的两个关键区别：

1. **不再猴子补丁 Route.endpoint**。Starlette 的 `Route.__init__` 里就执行了
   `self.app = request_response(endpoint)`，改属性对分发毫无影响——v1 的加固
   因此在运行期完全失效。v2 改为**重建路由表**，把 base 的处理函数包在守卫里。
2. **不再用 `app.middleware("http")` 装饰器**。该方法在 Starlette 1.x 已被移除，
   v1 在原样安装依赖的环境下直接启动失败。令牌校验改为在端点包装函数里做，
   同时避免中间件缓冲 SSE 流。

令牌来源支持三种：`Authorization: Bearer`、`X-NetCLI-Token`，以及页面下发的
HttpOnly Cookie——后者让内置网页与 EventSource 无需改动即可携带令牌。
"""
import json
import os
import re

import uvicorn
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

try:
    import console.app as base          # 仓库布局：<repo>/console/app.py
except ImportError:                      # 扁平部署：<dir>/app.py
    import app as base
from security import (
    APPROVAL_MODE,
    APPROVAL_SECRET,
    MAX_OUTPUT_CHARS,
    MAX_WAIT_MS,
    POLICY,
    audit,
    check_command,
    check_serial_port,
    check_target,
    check_token,
    sanitize,
)

COOKIE_NAME = "netcli_token"
_LOOPBACK_ORIGIN = re.compile(r"(?i)^https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$")

# ---------------------------------------------------------------- 事件脱敏

_original_push = base.push


def _redacting_push(kind: str, **payload):
    """SSE 广播前统一脱敏，避免窗口里出现设备密码哈希。"""
    safe = {k: sanitize(v) for k, v in payload.items()}
    if isinstance(safe.get("text"), str):
        safe["text"] = safe["text"][:MAX_OUTPUT_CHARS]
    return _original_push(kind, **safe)


base.push = _redacting_push  # console.app 内部按模块全局名解析 push，替换即时生效


# ---------------------------------------------------------------- 令牌

def _token_from(request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    for candidate in (
        request.headers.get("x-netcli-token"),
        request.cookies.get(COOKIE_NAME),
        request.query_params.get("token"),
    ):
        if candidate:
            return candidate.strip()
    return ""


def _authorized(request) -> tuple[bool, str, int]:
    if not check_token(_token_from(request)):
        return False, "缺少或无效的 NETCLI_API_TOKEN", 401
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin and not _LOOPBACK_ORIGIN.match(origin):
            return False, "拒绝跨站请求", 403
    return True, "", 200


def protected(endpoint):
    """令牌 + 同源校验；放在端点层而不是中间件层，避免缓冲 SSE。"""

    async def wrapper(request):
        ok, reason, status = _authorized(request)
        if not ok:
            audit("api_denied", path=request.url.path, reason=reason)
            return JSONResponse({"ok": False, "error": reason}, status_code=status)
        return await endpoint(request)

    wrapper.__name__ = getattr(endpoint, "__name__", "endpoint")
    return wrapper


# ---------------------------------------------------------------- 页面

async def page(request):
    html = (base.BASE / "static" / "index.html").read_text(encoding="utf-8")
    response = HTMLResponse(html)
    token = os.getenv("NETCLI_API_TOKEN", "").strip()
    if token:
        # HttpOnly：页面脚本读不到，但 EventSource / fetch 会自动带上
        response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict", path="/")
    return response


# ---------------------------------------------------------------- 受控端点

async def api_connect_guarded(request):
    body = await request.json() if await request.body() else {}
    transport = (body.get("transport") or "telnet").lower()
    host = (body.get("host") or "").strip()

    if not host:
        return JSONResponse({"ok": False, "error": "缺少目标地址"}, status_code=400)
    ok, reason = (check_serial_port(host) if transport == "serial" else check_target(host))
    if not ok:
        audit("connect_denied", transport=transport, host=host, reason=reason)
        return JSONResponse({"ok": False, "error": reason}, status_code=403)

    response = await base.api_connect(request)
    audit("connect", transport=transport, host=host, port=body.get("port"),
          allowed=response.status_code == 200)
    return response


async def api_exec_guarded(request):
    body = await request.json() if await request.body() else {}
    command = (body.get("command") or "").rstrip("\r\n")
    session_id = base._state.get("sessionId") or ""

    allowed, reason, risk = check_command(command, body.get("approval") or "", session_id)
    if not allowed:
        audit("command_denied", session_id=session_id, command=command, reason=reason, risk=risk)
        payload = {"ok": False, "error": reason}
        # 只有 guarded 下的写操作才是"等你审批"；readonly 属于被策略禁止，不应提示可审批
        needs_approval = risk == "write" and POLICY == "guarded"
        if needs_approval:
            # 只回传 session_id，不回传任何可用作审批凭据的值
            payload.update({"approvalRequired": True, "sessionId": session_id})
        return JSONResponse(payload, status_code=428 if needs_approval else 400)

    try:
        body["wait_ms"] = min(max(int(body.get("wait_ms") or 15000), 1000), MAX_WAIT_MS)
    except (TypeError, ValueError):
        body["wait_ms"] = 15000
    # Starlette 会缓存 request.body()，改写后下游读到的是这份
    request._body = json.dumps(body).encode("utf-8")

    response = await base.api_exec(request)

    try:
        data = json.loads(response.body)
    except (AttributeError, TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        data = sanitize(data)
        audit("command", session_id=session_id, command=command, risk=risk,
              approved=risk == "write", ok=response.status_code == 200)
        return JSONResponse(data, status_code=response.status_code)

    audit("command", session_id=session_id, command=command, risk=risk,
          approved=risk == "write", ok=response.status_code == 200)
    return response


async def api_policy(request):
    """把当前生效的策略暴露给前端/Agent 自查（不含审批码本身）。"""
    return JSONResponse({
        "ok": True,
        "policy": POLICY,
        "approvalMode": APPROVAL_MODE,
        "approvalSecretConfigured": bool(APPROVAL_SECRET),
        "writesEnabled": POLICY == "unrestricted" or (
            APPROVAL_MODE == "off" or (APPROVAL_MODE == "echo" or bool(APPROVAL_SECRET))
        ) and POLICY != "readonly",
        "tokenRequired": bool(os.getenv("NETCLI_API_TOKEN", "").strip()),
        "allowedHosts": [x for x in os.getenv("NETCLI_ALLOWED_HOSTS", "").split(",") if x.strip()],
        "allowedSerialPorts": [x for x in os.getenv("NETCLI_ALLOWED_SERIAL_PORTS", "").split(",") if x.strip()],
    })


app = Starlette(routes=[
    Route("/", page),
    Route("/api/stream", protected(base.api_stream)),
    Route("/api/status", protected(base.api_status)),
    Route("/api/serialports", protected(base.api_serialports)),
    Route("/api/policy", protected(api_policy)),
    Route("/api/connect", protected(api_connect_guarded), methods=["POST"]),
    Route("/api/exec", protected(api_exec_guarded), methods=["POST"]),
    Route("/api/disconnect", protected(base.api_disconnect), methods=["POST"]),
    Route("/api/clear", protected(base.api_clear), methods=["POST"]),
])


def startup_report() -> None:
    print(f"[net-cli-mcp] console -> http://{base.HOST}:{base.PORT}")
    print(f"[net-cli-mcp] policy={POLICY} approval={APPROVAL_MODE} "
          f"secret={'set' if APPROVAL_SECRET else 'unset'} "
          f"token={'set' if os.getenv('NETCLI_API_TOKEN', '').strip() else 'unset'}")
    if POLICY == "guarded" and APPROVAL_MODE == "secret" and not APPROVAL_SECRET:
        print("[net-cli-mcp] 注意：未设置 NETCLI_APPROVAL_SECRET，写操作将被拒绝（fail-closed）")
    if POLICY == "guarded" and APPROVAL_MODE == "echo":
        print("[net-cli-mcp] 警告：NETCLI_APPROVAL_MODE=echo，审批串可被自动构造，仅限实验环境")


if __name__ == "__main__":
    startup_report()
    uvicorn.run(app, host=base.HOST, port=base.PORT, log_level="warning")
