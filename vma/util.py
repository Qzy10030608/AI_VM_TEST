# -*- coding: utf-8 -*-
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import time
import uuid

from .cfg import (
    CONFIG, WORKSPACE_ROOT, TEST_ROOT, RUNTIME_ROOT, TEMP_ROOT, DOWNLOADS_ROOT,
    APPS_ROOT, MOVED_ROOT, UPDATES_ROOT, BACKUPS_ROOT, QUARANTINE_ROOT,
    DEFAULT_TIMEOUT_SEC, PROTOCOL_VERSION, PACKAGE_VERSION,
)

def ensure_dirs() -> None:
    for path in (
        TEST_ROOT,
        WORKSPACE_ROOT,
        RUNTIME_ROOT,
        RUNTIME_ROOT / "requests",
        RUNTIME_ROOT / "responses",
        RUNTIME_ROOT / "logs",
        TEMP_ROOT,
        DOWNLOADS_ROOT,
        APPS_ROOT,
        MOVED_ROOT,
        UPDATES_ROOT,
        BACKUPS_ROOT,
        QUARANTINE_ROOT,
    ):
        path.mkdir(parents=True, exist_ok=True)


def now_ms() -> int:
    return int(time.time() * 1000)


def new_request_id() -> str:
    return f"vm-{int(time.time())}-{uuid.uuid4().hex[:8]}"


def normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def process_timeout(options: dict[str, Any] | None = None) -> int:
    options = options if isinstance(options, dict) else {}
    raw = options.get("timeout_sec", DEFAULT_TIMEOUT_SEC)
    try:
        value = int(raw)
    except Exception:
        value = DEFAULT_TIMEOUT_SEC
    return max(1, min(value, 120))


def creation_flags() -> int:
    return subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0


def safe_id(text: str) -> str:
    digest = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"vm_app_{digest}"


def safe_filename(value: str) -> str:
    text = str(value or "app").strip() or "app"
    for ch in '<>:"/\\|?*':
        text = text.replace(ch, "_")
    return text.strip(" .") or "app"


def build_hash() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:16]
    except Exception:
        return ""


def is_running_as_admin() -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    except Exception:
        return False


def vm_agent_feature_flags() -> dict[str, bool]:
    action_api = normalize_bool(CONFIG.get("allow_action_api", True))
    app_move_enabled = normalize_bool(CONFIG.get("enable_app_move", False))
    return {
        "dynamic_scan": normalize_bool(CONFIG.get("allow_dynamic_app_scan", True)),
        "action_api": action_api,
        "installed_app_relocate": bool(action_api and app_move_enabled),
        "move_update_paths": bool(action_api and app_move_enabled),
        "vm_folder_dialog": True,
        "copy_junction": False,
        "registry_path_update": bool(action_api and app_move_enabled),
        "shortcut_path_update": bool(action_api and app_move_enabled),
        "service_path_update": bool(action_api and app_move_enabled),
        "file_actions": normalize_bool(CONFIG.get("enable_file_write_actions", False)),
        "allow_any_vm_file_read": normalize_bool(CONFIG.get("allow_any_vm_file_read", False)),
        "allow_any_vm_file_write": normalize_bool(CONFIG.get("allow_any_vm_file_write", False)),
        "is_admin": is_running_as_admin(),
    }


def clean_string(value: Any) -> str:
    return str(value or "").strip()


def expand_path(value: str) -> str:
    if not value:
        return ""
    return os.path.expandvars(value.strip().strip('"'))


def resolve_path(value: str | None, *, base: Path | None = None) -> Path:
    if not value:
        return (base or WORKSPACE_ROOT).resolve(strict=False)

    path = Path(expand_path(str(value)))
    if not path.is_absolute():
        path = (base or WORKSPACE_ROOT) / path
    return path.expanduser().resolve(strict=False)


def is_under(child: Path, root: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except Exception:
        return False


def deny_reason_for_path(path: Path) -> str:
    deny_roots = CONFIG.get("deny_roots", [])
    if not isinstance(deny_roots, list):
        deny_roots = []

    resolved = path.resolve(strict=False)
    for raw in deny_roots:
        if not raw:
            continue
        root = Path(expand_path(str(raw))).resolve(strict=False)
        if resolved == root or is_under(resolved, root):
            return f"path_denied_by_vm_min_boundary: {root}"
    return ""


def first_existing(paths: list[str]) -> str:
    for raw in paths:
        if not raw:
            continue
        path = Path(expand_path(raw))
        try:
            if path.exists():
                return str(path.resolve(strict=False))
        except Exception:
            continue
    return ""


def find_first_exe_in_dir(directory: str) -> str:
    if not directory:
        return ""
    root = Path(expand_path(directory))
    if not root.exists() or not root.is_dir():
        return ""

    try:
        for child in root.iterdir():
            if child.is_file() and child.suffix.lower() == ".exe":
                return str(child.resolve(strict=False))
    except Exception:
        return ""
    return ""


def path_short(path: str, max_len: int = 72) -> str:
    text = clean_string(path)
    if len(text) <= max_len:
        return text or "-"
    return "..." + text[-(max_len - 3):]


def receipt(
    *,
    ok: bool,
    action: str,
    request_id: str = "",
    message: str = "",
    data: dict[str, Any] | None = None,
    error: str = "",
    status: str = "",
) -> dict[str, Any]:
    return {
        "ok": bool(ok),
        "request_id": request_id or new_request_id(),
        "protocol_version": PROTOCOL_VERSION,
        "agent": "desktop_vm_agent",
        "package_version": PACKAGE_VERSION,
        "executed_in": "vm",
        "action": str(action or ""),
        "hostname": platform.node(),
        "system": platform.platform(),
        "pid": os.getpid(),
        "timestamp_ms": now_ms(),
        "message": str(message or ("OK" if ok else "Failed")),
        "status": str(status or ("ok" if ok else "error")),
        "data": data or {},
        "error": str(error or ""),
    }


def json_response(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
    handler.end_headers()
    handler.wfile.write(body)


def run_command(args: list[str] | str, *, timeout_sec: int, shell: bool = False) -> dict[str, Any]:
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        shell=shell,
        check=False,
        creationflags=creation_flags(),
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _taskkill_process_not_found(result: dict[str, Any]) -> bool:
    text = " ".join([
        str(result.get("stdout", "") or ""),
        str(result.get("stderr", "") or ""),
        str(result.get("error", "") or ""),
    ]).lower()

    return any(marker in text for marker in (
        # English
        "not found",
        "not running",
        "no running instance",
        "there is no running instance",
        "no tasks are running",
        "the process",
        "could not be found",

        # Chinese Windows taskkill messages
        "没有找到进程",
        "没有找到",
        "找不到进程",
        "找不到",
        "未找到进程",
        "未找到",
        "没有运行",
        "未运行",

        # Escaped/unicode-safe equivalents
        "\u6ca1\u6709\u627e\u5230\u8fdb\u7a0b",  # 没有找到进程
        "\u6ca1\u6709\u627e\u5230",              # 没有找到
        "\u627e\u4e0d\u5230\u8fdb\u7a0b",        # 找不到进程
        "\u627e\u4e0d\u5230",                    # 找不到
        "\u672a\u627e\u5230\u8fdb\u7a0b",        # 未找到进程
        "\u672a\u627e\u5230",                    # 未找到
        "\u672a\u8fd0\u884c",                    # 未运行
        "\u6ca1\u6709\u8fd0\u884c",              # 没有运行
    ))


def _ps_single_quote(value: str) -> str:
    """
    PowerShell 单引号字符串转义。
    """
    return "'" + str(value or "").replace("'", "''") + "'"


def select_vm_folder_via_dialog(*, title: str, initial_dir: str) -> str:
    """
    在虚拟机内部弹出文件夹选择窗口。

    注意：
    - 这是 VM 内部窗口，不是 Host 控制中心窗口。
    - 用户选择的是 VM 内路径。
    - 返回值是用户选择的 VM 文件夹路径。
    - 用户取消时返回空字符串。
    """
    safe_title = _ps_single_quote(title)
    safe_initial_dir = _ps_single_quote(initial_dir)

    ps = rf"""
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = {safe_title}
$dialog.SelectedPath = {safe_initial_dir}
$dialog.ShowNewFolderButton = $true

$result = $dialog.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {{
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $dialog.SelectedPath
}}
"""

    try:
        result = run_command(
            [
                "powershell",
                "-NoProfile",
                "-STA",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps,
            ],
            timeout_sec=300,
        )
    except Exception:
        return ""

    try:
        rc = int(result.get("returncode", 1))
    except Exception:
        rc = 1

    if rc != 0:
        return ""

    stdout = str(result.get("stdout", "") or "").strip()
    if not stdout:
        return ""

    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def action_not_enabled(payload: dict[str, Any], action: str, reason: str = "") -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    return receipt(
        ok=False,
        request_id=request_id,
        action=action,
        message=f"{action} is not enabled in VM Agent config.",
        error=reason or "action_not_enabled_in_agent_config",
        data={
            "config_hint": "Enable the corresponding flag in agent_config.json only after Host-side governance is ready.",
        },
    )
