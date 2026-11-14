@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0.."

echo ============================================================
echo  网络设备实时控制台  ==  安全加固版
echo ============================================================
echo  写操作（sys / save / undo / 改配置）需要审批码；
echo  审批码只在本进程环境里生效，不写进任何文件。
echo  直接回车 = 以只读模式启动，写操作全部拒绝。
echo.
set "CODE="
set /p "CODE=请输入审批码（直接回车=只读模式）: "

if defined CODE (
  set "NETCLI_COMMAND_POLICY=guarded"
  set "NETCLI_APPROVAL_MODE=secret"
  set "NETCLI_APPROVAL_SECRET=%CODE%"
  echo [模式] guarded：查询直接执行，写操作需审批
) else (
  set "NETCLI_COMMAND_POLICY=readonly"
  echo [模式] readonly：未提供审批码，写操作全部拒绝
)

set "NETCLI_AUDIT_LOG=%~dp0logs\audit.jsonl"
if not exist "%~dp0logs" mkdir "%~dp0logs"

rem 先停掉占用 8199 的旧实例，避免端口冲突
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8199" ^| findstr "LISTENING"') do (
  echo [提示] 停止占用 8199 的旧进程 PID=%%p（如有设备会话会被断开）
  taskkill /PID %%p /F >nul 2>&1
)

start "net-console-secure" /min python "%~dp0..\secure_console.py"
timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:8199

echo.
echo 已启动：http://127.0.0.1:8199
echo 服务在最小化的 "net-console-secure" 窗口里运行，关闭该窗口即停止。
timeout /t 3 /nobreak >nul
