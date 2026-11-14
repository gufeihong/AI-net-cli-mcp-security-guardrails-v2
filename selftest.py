"""v2 自测：全部基于 Starlette TestClient，不连接任何设备。

用法：python selftest.py     （退出码 0 = 全绿）
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# 必须在 import security 之前设好：策略在模块导入时求值
_SECRET = "s3cr3t-approval-code"
_AUDIT = Path(tempfile.gettempdir()) / "netcli_selftest_audit.jsonl"
if _AUDIT.exists():
    _AUDIT.unlink()
os.environ.update({
    "NETCLI_COMMAND_POLICY": "guarded",
    "NETCLI_APPROVAL_MODE": "secret",
    "NETCLI_APPROVAL_SECRET": _SECRET,
    "NETCLI_AUDIT_LOG": str(_AUDIT),
    "NETCLI_ALLOWED_HOSTS": "10.0.0.0/8,sw-lab.local",
})
os.environ.pop("NETCLI_API_TOKEN", None)

import security  # noqa: E402
import secure_console  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

PASS, FAIL = 0, 0
FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        FAILED.append(name)
        print(f"  FAIL  {name}  {detail}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


# ------------------------------------------------------------ 命令分类

section("命令分类")
cases = {
    "display version": "read",
    "display interface brief": "read",
    "display this interface": "read",
    "display current-configuration": "read",
    "show running-config": "read",
    "display current-configuration | include password": "read",
    "display current-configuration | include interface": "read",
    "display logbuffer | include ERROR | exclude DEBUG": "read",
    "ping 10.1.1.1": "read",
    "terminal length 0": "read",
    "save": "write",
    "system-view": "write",
    "undo interface GigabitEthernet1/0/1": "write",
    "interface GigabitEthernet1/0/1": "write",
    "vlan 100": "write",
    "display version | save": "write",
    "display version ; save": "invalid",
    "display version\r\nsave": "invalid",
    "display version `whoami`": "invalid",
    "": "invalid",
}
for cmd, expected in cases.items():
    got = security.classify(cmd)
    check(f"classify({cmd!r}) == {expected}", got == expected, f"got {got}")

# ------------------------------------------------------------ 审批

section("审批码")
sid = "sess-abc"
ok, reason, risk = security.check_command("save", "", sid)
check("无审批码 → 拒绝", not ok and risk == "write")
check("报错不含审批码原文", _SECRET not in reason, reason)
check("报错给出格式说明", "审批码" in reason)

ok, _, _ = security.check_command("save", "WRONG", sid)
check("错误审批码 → 拒绝", not ok)

ok, _, _ = security.check_command("save", f"CONFIRM {sid} {_SECRET}", sid)
check("正确审批码 → 放行", ok)

ok, _, _ = security.check_command("save", _SECRET, sid)
check("只填审批码也能识别", ok)

ok, _, _ = security.check_command("save", f"CONFIRM other-session {_SECRET}", sid)
check("会话不匹配 → 拒绝", not ok)

ok, _, _ = security.check_command("display version", "", sid)
check("查询命令免审批", ok)

# 未配置审批码时必须 fail-closed
_saved = security.APPROVAL_SECRET
security.APPROVAL_SECRET = ""
ok, reason, _ = security.check_command("save", "anything", sid)
check("未配置审批码 → 写操作拒绝（fail-closed）", not ok)
security.APPROVAL_SECRET = _saved

# ------------------------------------------------------------ 脱敏

section("脱敏")
redact_cases = [
    ("local-user admin password irreversible-cipher $1c$Vm)EZN7Dx9g.!=abcd",
     ["$1c$", "Vm)EZN7Dx"]),
    ("local-user ssh password cipher %^%#JvZxR2abc%^%#", ["JvZxR2"]),
    ("password simple Huawei@123", ["Huawei@123"]),
    ("local-user test password irreversible-cipher $9$ABCdef123", ["ABCdef123"]),
    ("snmp-agent community read public", ["public"]),
    ("snmp-server community rw secret123", ["secret123"]),
    ("radius-server shared-key cipher MyKey@2024", ["MyKey@2024"]),
    ("user-password: hello123", ["hello123"]),
]
for raw, leaks in redact_cases:
    out = security.redact_text(raw)
    leaked = [x for x in leaks if x in out]
    check(f"脱敏 {raw[:42]}…", not leaked, f"残留 {leaked} → {out}")

check("保留指令主体", security.redact_text("local-user admin password cipher x").startswith("local-user admin password"))

# ------------------------------------------------------------ 控制台端到端

section("控制台 /api 守卫")
client = TestClient(secure_console.app)

route_names = {getattr(r, "path", None): getattr(getattr(r, "endpoint", None), "__name__", "")
               for r in secure_console.app.routes}
check("路由已重建为守卫函数", "guarded" in route_names.get("/api/exec", ""), str(route_names.get("/api/exec")))
check("connect 路由已重建", "guarded" in route_names.get("/api/connect", ""))

r = client.post("/api/exec", json={"command": "save"})
check("/api/exec save → 428", r.status_code == 428, f"{r.status_code} {r.text[:120]}")
body = r.json()
check("428 回传 approvalRequired", body.get("approvalRequired") is True)
check("428 不回传审批码", _SECRET not in r.text)

r = client.post("/api/exec", json={"command": "display interface brief"})
check("/api/exec 查询命令 → 通过守卫", r.status_code == 409, f"{r.status_code} {r.text[:120]}")

r = client.post("/api/exec", json={"command": "display current-configuration | include password"})
check("/api/exec 管道过滤 → 通过守卫", r.status_code == 409, f"{r.status_code} {r.text[:120]}")

r = client.post("/api/exec", json={"command": "save", "approval": f"CONFIRM {body.get('sessionId','')} {_SECRET}"})
check("/api/exec save + 审批码 → 通过守卫", r.status_code == 409, f"{r.status_code} {r.text[:120]}")

r = client.post("/api/exec", json={"command": "display version ; save"})
check("/api/exec 多命令 → 400", r.status_code == 400, f"{r.status_code}")

r = client.post("/api/connect", json={"host": "8.8.8.8", "port": 23})
check("/api/connect 非白名单 → 403", r.status_code == 403, f"{r.status_code} {r.text[:120]}")

r = client.post("/api/connect", json={"host": "sw-lab.local", "port": 23})
check("/api/connect 白名单主机 → 通过守卫", r.status_code != 403, f"{r.status_code}")

# ------------------------------------------------------------ 令牌

section("API 令牌")
os.environ["NETCLI_API_TOKEN"] = "tok-123456"
try:
    r = client.post("/api/exec", json={"command": "display version"})
    check("无令牌 → 401", r.status_code == 401, f"{r.status_code}")

    r = client.post("/api/exec", json={"command": "display version"},
                    headers={"Authorization": "Bearer tok-123456"})
    check("Bearer 令牌 → 放行", r.status_code == 409, f"{r.status_code}")

    r = client.post("/api/exec", json={"command": "display version"},
                    headers={"X-NetCLI-Token": "tok-123456"})
    check("自定义头令牌 → 放行", r.status_code == 409, f"{r.status_code}")

    r = client.post("/api/exec", json={"command": "display version"}, params={"token": "tok-123456"})
    check("查询参数令牌 → 放行", r.status_code == 409, f"{r.status_code}")

    r = client.get("/")
    check("页面下发 HttpOnly Cookie", secure_console.COOKIE_NAME in r.cookies, str(r.cookies))

    r = client.post("/api/exec", json={"command": "display version"},
                    headers={"Origin": "http://evil.example"})
    check("跨站 Origin → 403", r.status_code == 403, f"{r.status_code}")
finally:
    os.environ.pop("NETCLI_API_TOKEN", None)

# ------------------------------------------------------------ 策略自省与审计

section("策略自省 / 审计")
r = client.get("/api/policy")
data = r.json()
check("/api/policy 可用", r.status_code == 200 and data.get("policy") == "guarded", r.text[:120])
check("/api/policy 不泄露审批码", _SECRET not in r.text)

lines = _AUDIT.read_text(encoding="utf-8").splitlines() if _AUDIT.exists() else []
records = [json.loads(x) for x in lines]
kinds = {x.get("action") for x in records}
check("审计有拒绝记录", "command_denied" in kinds, str(kinds))
check("审计含 command 记录", "command" in kinds or "connect_denied" in kinds, str(kinds))
check("审计不含明文审批码", _SECRET not in _AUDIT.read_text(encoding="utf-8"))

# ------------------------------------------------------------ 只读策略

section("只读策略")
import importlib  # noqa: E402

os.environ["NETCLI_COMMAND_POLICY"] = "readonly"
importlib.reload(security)
importlib.reload(secure_console)
c2 = TestClient(secure_console.app)
r = c2.post("/api/exec", json={"command": "save", "approval": f"CONFIRM x {_SECRET}"})
check("readonly 下写操作 → 400", r.status_code == 400, f"{r.status_code} {r.text[:120]}")
r = c2.post("/api/exec", json={"command": "display clock"})
check("readonly 下查询 → 通过", r.status_code == 409, f"{r.status_code}")

# ------------------------------------------------------------ 汇总

print(f"\n{'=' * 46}")
print(f"PASS {PASS}  FAIL {FAIL}")
if FAILED:
    print("失败项：")
    for name in FAILED:
        print("  -", name)
print(f"starlette {__import__('starlette').__version__}")
sys.exit(0 if FAIL == 0 else 1)
