"""Hardened MCP entrypoint (v2).

把 MCP 客户端配置成启动本文件，而不是 server.py。原始 server.py 保持不动，
两者可以并存：不走安全入口就等于没有这些保护。

工具名、参数与 server.py 保持一致，Agent 侧无需改 prompt；写操作多一个
`approval` 参数，值由人类提供（不是服务端回显出来的字符串）。
"""
import json
import os

from mcp.server.fastmcp import FastMCP

import server as core
from security import (
    APPROVAL_MODE,
    MAX_OUTPUT_CHARS,
    MAX_WAIT_MS,
    POLICY,
    audit,
    check_command,
    check_serial_port,
    check_target,
    redact_text,
)

mcp = FastMCP("Network CLI MCP Server (guarded)")


def _json_result(raw: str) -> dict:
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {"success": True, "result": data}
    except (TypeError, ValueError):
        return {"success": False, "error": redact_text(str(raw))[:MAX_OUTPUT_CHARS]}


def _deny(error: str, **extra) -> str:
    return json.dumps({"success": False, "error": error, **extra}, ensure_ascii=False)


# ---------------------------------------------------------------- 连接

@mcp.tool()
async def telnet_connect(host: str, port: int = 23, timeout: int = 5000,
                         username: str = "", password: str = "") -> str:
    """Telnet 连接目标设备，返回会话ID。目标受 NETCLI_ALLOWED_HOSTS 白名单约束。"""
    ok, reason = check_target(host)
    if not ok:
        audit("connect_denied", transport="telnet", host=host, reason=reason)
        return _deny(reason)
    result = await core.telnet_connect(host, port, timeout, username, password)
    audit("connect", transport="telnet", host=host, port=port)
    return redact_text(result)[:MAX_OUTPUT_CHARS]


@mcp.tool()
async def ssh_connect(host: str, port: int = 22, username: str = "", password: str = "",
                      timeout: int = 10000) -> str:
    """SSH 连接目标设备。目标受 NETCLI_ALLOWED_HOSTS 白名单约束。"""
    ok, reason = check_target(host)
    if not ok:
        audit("connect_denied", transport="ssh", host=host, reason=reason)
        return _deny(reason)
    result = await core.ssh_connect(host, port, username, password, timeout)
    audit("connect", transport="ssh", host=host, port=port)
    return redact_text(result)[:MAX_OUTPUT_CHARS]


@mcp.tool()
async def serial_connect(com_port: str, baudrate: int = 9600,
                         username: str = "", password: str = "") -> str:
    """连接本机 Console 串口。可用 NETCLI_ALLOWED_SERIAL_PORTS 限定允许的串口。"""
    ok, reason = check_serial_port(com_port)
    if not ok:
        audit("connect_denied", transport="serial", port=com_port, reason=reason)
        return _deny(reason)
    result = await core.serial_connect(com_port, baudrate, username, password)
    audit("connect", transport="serial", port=com_port, baudrate=baudrate)
    return redact_text(result)[:MAX_OUTPUT_CHARS]


# ---------------------------------------------------------------- 执行

@mcp.tool()
async def telnet_execute(session_id: str, command: str, wait_ms: int = 2000,
                         approval: str = "") -> str:
    """在会话中执行一条 CLI 命令。

    查询类命令（display/show/ping 等，可带 include/exclude/begin 管道过滤）直接执行；
    写操作必须由人类提供申请码，通过 approval 参数传入。
    """
    allowed, reason, risk = check_command(command, approval, session_id)
    if not allowed:
        audit("command_denied", session_id=session_id, command=command, reason=reason, risk=risk)
        extra = {"approvalRequired": True} if risk == "write" else {}
        return _deny(reason, **extra)

    try:
        bounded_wait = min(max(int(wait_ms), 1000), MAX_WAIT_MS)
    except (TypeError, ValueError):
        bounded_wait = 2000

    result = _json_result(await core.telnet_execute(session_id, command, bounded_wait))
    if isinstance(result.get("output"), str):
        result["output"] = redact_text(result["output"])[:MAX_OUTPUT_CHARS]
    audit("command", session_id=session_id, command=command, risk=risk,
          approved=risk == "write", success=result.get("success", False))
    return json.dumps(result, ensure_ascii=False)


@mcp.tool()
def telnet_list_sessions() -> str:
    """列出当前所有活动会话。"""
    return redact_text(core.telnet_list_sessions())[:MAX_OUTPUT_CHARS]


@mcp.tool()
def serial_list_ports() -> str:
    """列出本机可用串口。"""
    return redact_text(core.serial_list_ports())[:MAX_OUTPUT_CHARS]


@mcp.tool()
async def telnet_disconnect(session_id: str) -> str:
    """断开指定会话。"""
    result = await core.telnet_disconnect(session_id)
    audit("disconnect", session_id=session_id)
    return redact_text(result)


def main() -> None:
    # 启动时把当前策略打到 stderr，便于确认"加固真的生效了"
    import sys

    print(
        f"[net-cli-mcp] policy={POLICY} approval={APPROVAL_MODE} "
        f"secret={'set' if os.getenv('NETCLI_APPROVAL_SECRET') else 'unset'}",
        file=sys.stderr,
    )
    mcp.run()


if __name__ == "__main__":
    main()
