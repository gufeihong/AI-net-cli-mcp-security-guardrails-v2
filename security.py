"""Shared guardrails for the hardened MCP and local web entrypoints (v2).

设计原则（按"出错就拒绝"排列优先级）：
1. 只读判定用**前缀白名单**，不做危险词黑名单——黑名单只会误杀
   `display interface brief` 这类正常查询，真正的写命令本来就不会以
   display/show 开头。
2. 管道只放行过滤段（include / exclude / begin），其余一律视为未知写操作。
3. 写操作必须带**审批码**，且审批码来自 Agent 读不到的进程环境变量；
   服务端不会在报错里回显期望值（v1 的致命缺陷）。
4. 脱敏按"先具体后通用"排序，并单独兜底华为 `$1c$` / Comware `%^%#` 哈希。

配置项见 docs/security-hardening.md。
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------- 配置

POLICY = os.getenv("NETCLI_COMMAND_POLICY", "guarded").strip().lower()
if POLICY not in {"guarded", "readonly", "unrestricted"}:
    POLICY = "guarded"

# secret: 必须提供 NETCLI_APPROVAL_SECRET 才允许写操作（默认，fail-closed）
# echo  : v1 兼容，审批串由会话ID拼出——Agent 可自行构造，仅用于实验环境
# off   : 不审批（等价于把工具交给模型全权操作，不建议）
APPROVAL_MODE = os.getenv("NETCLI_APPROVAL_MODE", "secret").strip().lower()
if APPROVAL_MODE not in {"secret", "echo", "off"}:
    APPROVAL_MODE = "secret"
APPROVAL_SECRET = os.getenv("NETCLI_APPROVAL_SECRET", "")

MAX_OUTPUT_CHARS = max(1024, int(os.getenv("NETCLI_MAX_OUTPUT_CHARS", "65536")))
MAX_WAIT_MS = max(1000, int(os.getenv("NETCLI_MAX_WAIT_MS", "120000")))
MAX_SANITIZE_DEPTH = 8

# ---------------------------------------------------------------- 命令判定

_READ_ONLY_VERB = re.compile(
    r"(?i)^\s*(?:"
    r"display|show|"
    r"ping|ping6|tracert|traceroute|"
    r"terminal[ \t]+length|screen-length|"
    r"dir|more|help|\?|"
    r"quit|exit|return|end"
    r")\b"
)

# 管道后只允许这几类过滤关键字，别的一律当写操作
_FILTER_VERB = re.compile(r"(?i)^(?:include|exclude|begin|section|grep)[ \t]+\S")

# 多命令 / 控制字符：分号、换行、反引号、&&、|| 一律拒绝
_CONTROL = re.compile(r"[\r\n\x00;`]|&&|\|\||[ \t]&[ \t]")

# ---------------------------------------------------------------- 脱敏

# 这些格式本身就是密文，出现即替换，不依赖上下文关键词
_HASH_ONLY = [
    re.compile(r"\$1c\$[^\s\"']+"),          # 华为 irreversible-cipher
    re.compile(r"\$9\$[^\s\"']+"),           # Comware V7
    re.compile(r"%\^%#[^\s\"']*?%\^%#"),     # Comware V5 可逆密文
]

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    # 1) SNMP 社区串：先于通用规则，否则只会脱掉 read/write 而把真正的串留下
    (
        re.compile(
            r"(?i)\b(snmp-(?:agent|server)[ \t]+community[ \t]+)"
            r"((?:read|write|rw|ro)[ \t]+)?(?:cipher[ \t]+)?(\S+)"
        ),
        r"\1\2<REDACTED>",
    ),
    # 2) 通用口令：password / secret / shared-key，含 irreversible-cipher 存储类型
    (
        re.compile(
            r"(?i)\b((?:password|passwd|secret|auth-key|priv-key|shared-key|community)\b[ \t]+)"
            r"(?:(?:irreversible-|reversible-)?cipher|simple|plain|[0789])?[ \t]*(\S+)"
        ),
        r"\1<REDACTED>",
    ),
    # 3) key = value / key: value 形式
    (
        re.compile(r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)[ \t]*[:=][ \t]*(\S+)"),
        r"\1: <REDACTED>",
    ),
]


def redact_text(value: str) -> str:
    """先按上下文脱敏，再兜底抹掉裸密文哈希。"""
    text = value
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    for pattern in _HASH_ONLY:
        text = pattern.sub("<REDACTED>", text)
    return text


def sanitize(value: Any, _depth: int = 0) -> Any:
    if _depth > MAX_SANITIZE_DEPTH:
        return "<TRUNCATED>"
    if isinstance(value, str):
        return redact_text(value)[:MAX_OUTPUT_CHARS]
    if isinstance(value, list):
        return [sanitize(v, _depth + 1) for v in value]
    if isinstance(value, dict):
        return {k: sanitize(v, _depth + 1) for k, v in value.items()}
    return value


# ---------------------------------------------------------------- 命令策略

def classify(command: str) -> str:
    """返回 read / write / invalid。未知语法一律归为 write，由上层决定是否放行。"""
    if not isinstance(command, str) or not command.strip():
        return "invalid"
    if len(command) > 4096 or _CONTROL.search(command):
        return "invalid"
    base, *filters = command.split("|")
    if not _READ_ONLY_VERB.match(base.strip()):
        return "write"
    for filt in filters:
        if not _FILTER_VERB.match(filt.strip()):
            return "write"
    return "read"


def approval_hint(session_id: str = "") -> str:
    """给人类看的格式说明，不包含审批码本身。"""
    if APPROVAL_MODE == "off":
        return "当前审批已关闭（NETCLI_APPROVAL_MODE=off）"
    if APPROVAL_MODE == "echo":
        return f"实验模式：approval 传 CONFIRM {session_id or '<session_id>'}"
    return (
        f"需人工审批：approval 传 CONFIRM {session_id or '<session_id>'} <审批码>，"
        "审批码由设备负责人提供（服务端 NETCLI_APPROVAL_SECRET，Agent 不可读）"
    )


def _normalize_approval(approval: str, session_id: str) -> str:
    """允许只填审批码；也允许完整 CONFIRM 串。统一压掉多余空格。"""
    value = (approval or "").strip()
    if not value:
        return ""
    if value.upper().startswith("CONFIRM"):
        return " ".join(value.split())
    return " ".join(f"CONFIRM {session_id} {value}".split())


def check_command(command: str, approval: str | None = None, session_id: str = "") -> tuple[bool, str, str]:
    """返回 (allowed, reason, risk)。任何异常路径都必须返回 False。"""
    risk = classify(command)
    if risk == "invalid":
        return False, "拒绝空命令、超长命令，或包含多命令/控制字符的输入；请一次执行一条命令。", "invalid"

    if POLICY == "unrestricted":
        return True, "", risk
    if risk == "read":
        return True, "", "read"
    if POLICY == "readonly":
        return False, "只读策略下仅允许查询类命令，写操作已被策略拒绝。", "write"

    # guarded 且为写操作
    if APPROVAL_MODE == "off":
        return True, "", "write"
    if APPROVAL_MODE == "echo":
        expected = " ".join(f"CONFIRM {session_id}".split())
    else:
        if not APPROVAL_SECRET:
            return (
                False,
                "写操作已禁用：服务端未配置审批码（NETCLI_APPROVAL_SECRET）。"
                "请让操作者设置后重启，或临时使用 NETCLI_COMMAND_POLICY=readonly。",
                "write",
            )
        expected = " ".join(f"CONFIRM {session_id} {APPROVAL_SECRET}".split())

    provided = _normalize_approval(approval or "", session_id)
    if not provided or not secrets.compare_digest(provided, expected):
        # 注意：绝不回显 expected，避免 Agent 自助批准
        return False, f"该命令属于写操作，未获人工审批。{approval_hint(session_id)}", "write"
    return True, "", "write"


def check_target(host: str) -> tuple[bool, str]:
    """若设置 NETCLI_ALLOWED_HOSTS，则按精确主机名 / IP / CIDR 校验。"""
    allowed = [x.strip().lower() for x in os.getenv("NETCLI_ALLOWED_HOSTS", "").split(",") if x.strip()]
    if not allowed:
        return True, ""
    candidate = (host or "").strip().lower().rstrip(".")
    if not candidate:
        return False, "缺少目标地址"
    if candidate in allowed:
        return True, ""
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False, f"目标 {candidate} 不在 NETCLI_ALLOWED_HOSTS 白名单中"
    for item in allowed:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True, ""
        except ValueError:
            continue
    return False, f"目标 {candidate} 不在 NETCLI_ALLOWED_HOSTS 白名单中"


def check_serial_port(port: str) -> tuple[bool, str]:
    allowed = [x.strip().lower() for x in os.getenv("NETCLI_ALLOWED_SERIAL_PORTS", "").split(",") if x.strip()]
    if not allowed:
        return True, ""
    if (port or "").strip().lower() in allowed:
        return True, ""
    return False, f"串口 {port} 不在 NETCLI_ALLOWED_SERIAL_PORTS 白名单中"


def check_token(provided: str | None) -> bool:
    expected = os.getenv("NETCLI_API_TOKEN", "").strip()
    return not expected or bool(provided and secrets.compare_digest(provided, expected))


# ---------------------------------------------------------------- 审计

_audit_lock = threading.Lock()


def audit(action: str, **fields: Any) -> None:
    path = os.getenv("NETCLI_AUDIT_LOG", "").strip()
    if not path:
        return
    record = {"ts": datetime.now(timezone.utc).isoformat(), "action": action, **sanitize(fields)}
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        # 单进程内串行化；跨进程靠 O_APPEND 的原子性兜底
        with _audit_lock:
            with target.open("a", encoding="utf-8") as f:
                f.write(line)
        try:
            target.chmod(0o600)
        except OSError:
            pass
    except OSError:
        # 审计写失败不应把一次成功的设备操作变成隐藏失败
        pass
