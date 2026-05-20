@echo off
setlocal

cd /d C:\AI_VM_TEST

:: 检查当前是否管理员权限
net session >nul 2>&1
if %errorlevel%==0 (
    echo [AI_VM_TEST] Running as Administrator.
    python desktop_vm_agent.py
    pause
    exit /b
)

echo [AI_VM_TEST] Need Administrator permission.
echo [AI_VM_TEST] Restarting with UAC...

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -Verb RunAs -ArgumentList '/k cd /d C:\AI_VM_TEST && python desktop_vm_agent.py'"

exit /b