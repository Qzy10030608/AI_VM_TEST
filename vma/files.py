# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import os
import platform
import shutil
import subprocess
import time

from .cfg import CONFIG, WORKSPACE_ROOT, TEST_ROOT, QUARANTINE_ROOT, DEFAULT_TIMEOUT_SEC
from .util import (
    action_not_enabled,
    clean_string,
    deny_reason_for_path,
    expand_path,
    is_under,
    normalize_bool,
    new_request_id,
    now_ms,
    receipt,
    resolve_path,
    run_command,
    _ps_single_quote,
    _taskkill_process_not_found,
)

# ============================================================
# 文件区运行期状态
# ============================================================

OPEN_HANDLE_REGISTRY: dict[str, dict[str, Any]] = {}

TEXT_FILE_SUFFIXES = {".txt", ".log", ".json", ".md", ".csv"}

# ============================================================
# VM 少府：测试财产分仓
# ============================================================

SHAOFU_ROOT = (TEST_ROOT / "temp" / "shaofu").resolve(strict=False)

SHAOFU_FILES_ROOT = SHAOFU_ROOT / "files"
SHAOFU_APPS_ROOT = SHAOFU_ROOT / "apps"

SHAOFU_FILE_MOVE_TEMP_ROOT = SHAOFU_FILES_ROOT / "move_temp"
SHAOFU_FILE_MOVE_MANIFEST_DIR = SHAOFU_FILE_MOVE_TEMP_ROOT / "manifests"

SHAOFU_FILE_DELETE_ROOT = SHAOFU_FILES_ROOT / "delete_quarantine"
SHAOFU_FILE_DELETE_OBJECTS_DIR = SHAOFU_FILE_DELETE_ROOT / "objects"
SHAOFU_FILE_DELETE_MANIFEST_DIR = SHAOFU_FILE_DELETE_ROOT / "manifests"

SHAOFU_FILE_RESTORE_RECORDS_DIR = SHAOFU_FILES_ROOT / "restore_records"

# ============================================================
# 文件列表 / roots
# ============================================================

def list_directory(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    items: list[dict[str, Any]] = []
    for child in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        try:
            stat = child.stat()
            items.append({
                "name": child.name,
                "path": str(child),
                "is_dir": child.is_dir(),
                "type": "directory" if child.is_dir() else "file",
                "size": stat.st_size if child.is_file() else 0,
                "modified_at": stat.st_mtime,
            })
        except Exception as exc:
            items.append({
                "name": child.name,
                "path": str(child),
                "is_dir": child.is_dir(),
                "type": "unknown",
                "error": str(exc),
            })
    return items


def vm_file_roots() -> list[dict[str, Any]]:
    roots: list[dict[str, Any]] = []

    for drive in ("C", "D", "E", "F", "G"):
        root_path = Path(f"{drive}:/")
        if root_path.exists():
            roots.append({
                "root_id": f"vm_drive_{drive.lower()}",
                "title": f"{drive}:",
                "path": str(root_path.resolve(strict=False)),
                "permission_state": "test",
                "can_expand": True,
                "can_scan": True,
                "can_index": False,
                "file_actions_enabled": False,
                "is_system_drive": drive.upper() == "C",
            })

    test_root = TEST_ROOT.resolve(strict=False)
    if test_root.exists():
        roots.append({
            "root_id": "vm_test_root",
            "title": "AI_VM_TEST",
            "path": str(test_root),
            "permission_state": "test",
            "can_expand": True,
            "can_scan": True,
            "can_index": False,
            "file_actions_enabled": False,
            "is_test_root": True,
        })

    return roots


def default_vm_file_root_id() -> str:
    roots = vm_file_roots()
    for root in roots:
        if clean_string(root.get("root_id")) == "vm_drive_c":
            return "vm_drive_c"
    return clean_string(roots[0].get("root_id")) if roots else "vm_drive_c"


def vm_file_root_by_id(root_id: str) -> dict[str, Any] | None:
    normalized = clean_string(root_id) or default_vm_file_root_id()
    for root in vm_file_roots():
        if clean_string(root.get("root_id")) == normalized:
            return root
    return None


def safe_file_object_id(root_id: str, relative_path: str) -> str:
    text = f"{root_id}|{relative_path}".strip()
    digest = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"vm_file_{digest}"


def normalize_relative_path(value: Any) -> str:
    text = str(value or "").strip().strip("\\/")
    if not text:
        return ""
    text = text.replace("/", "\\")
    path = Path(text)
    if path.is_absolute():
        raise ValueError("absolute_relative_path_denied")
    parts = [part for part in path.parts if part not in {"", "."}]
    if any(part == ".." for part in parts):
        raise ValueError("relative_path_escape_denied")
    return str(Path(*parts)) if parts else ""


def resolve_vm_file_path(root_id: str, relative_path: Any = "") -> tuple[dict[str, Any], Path, str]:
    root = vm_file_root_by_id(root_id)
    if root is None:
        raise ValueError(f"unknown_root_id: {root_id or default_vm_file_root_id()}")
    normalized_relative = normalize_relative_path(relative_path)
    root_path = Path(str(root.get("path", ""))).resolve(strict=False)
    target = (root_path / normalized_relative).resolve(strict=False) if normalized_relative else root_path
    if target != root_path and not is_under(target, root_path):
        raise ValueError("relative_path_outside_root")
    denied = deny_reason_for_path(target)
    if denied:
        raise ValueError(denied)
    return root, target, normalized_relative


def parent_relative_path(relative_path: str) -> str:
    normalized = normalize_relative_path(relative_path)
    if not normalized:
        return ""
    parent = Path(normalized).parent
    return "" if str(parent) in {"", "."} else str(parent)


def list_directory_for_root(root_id: str, root_path: Path, current_path: Path) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in list_directory(current_path):
        child_path = Path(str(item.get("path", ""))).resolve(strict=False)
        try:
            relative = str(child_path.relative_to(root_path.resolve(strict=False)))
        except Exception:
            continue
        is_dir = bool(item.get("is_dir", False))
        denied_reason = deny_reason_for_path(child_path)
        items.append({
            **item,
            "object_id": safe_file_object_id(root_id, relative),
            "relative_path": relative,
            "object_type": "directory" if is_dir else "file",
            "modified_time": item.get("modified_at", ""),
            "permission_state": "test",
            "blocked": bool(denied_reason),
            "blocked_reason": denied_reason,
            "can_open": not bool(denied_reason),
            "open_action": "blocked" if denied_reason else ("navigate" if is_dir else "inspect"),
        })
    return items


def build_file_list_result(root_id: str = "vm_drive_c", relative_path: str = "") -> dict[str, Any]:
    started = now_ms()
    root, target, normalized_relative = resolve_vm_file_path(root_id, relative_path)
    if not target.exists():
        raise FileNotFoundError(f"not_found: {target}")
    if not target.is_dir():
        raise NotADirectoryError(f"not_directory: {target}")
    root_path = Path(str(root.get("path", ""))).resolve(strict=False)
    root_id_text = clean_string(root.get("root_id")) or default_vm_file_root_id()
    items = list_directory_for_root(root_id_text, root_path, target)
    return {
        "ok": True,
        "adapter_id": "vm",
        "executed_in": "vm",
        "action": "files.list",
        "hostname": platform.node(),
        "root_id": root_id_text,
        "root_path": str(root_path),
        "root": str(root_path),
        "relative_path": normalized_relative,
        "current_path": str(target),
        "parent_relative_path": parent_relative_path(normalized_relative),
        "count": len(items),
        "duration_ms": now_ms() - started,
        "items": items,
    }


# ============================================================
# 路径 / 权限
# ============================================================

def resolve_file_action_target(payload: dict[str, Any]) -> dict[str, Any]:
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    raw_path = (
        clean_string(target.get("path", ""))
        or clean_string(target.get("target_path", ""))
        or clean_string(target.get("source_path", ""))
        or clean_string(target.get("old_path", ""))
        or clean_string(target.get("original_path", ""))
    )
    path = resolve_path(raw_path, base=WORKSPACE_ROOT)
    target_type = clean_string(target.get("target_type", target.get("object_type", ""))).lower()
    if not target_type:
        target_type = "directory" if path.is_dir() else "file"
    return {
        "target": target,
        "path": path,
        "target_type": target_type,
        "root_id": clean_string(target.get("root_id", "")),
        "relative_path": clean_string(target.get("relative_path", "")),
    }


def config_path_roots(key: str) -> list[Path]:
    raw = CONFIG.get(key, [])
    if not isinstance(raw, list):
        return []
    roots: list[Path] = []
    for item in raw:
        text = clean_string(item)
        if not text:
            continue
        try:
            roots.append(Path(expand_path(text)).resolve(strict=False))
        except Exception:
            continue
    return roots


def is_under_any_root(path: Path, roots: list[Path]) -> bool:
    resolved = path.resolve(strict=False)
    for root in roots:
        try:
            root_resolved = root.resolve(strict=False)
            if resolved == root_resolved or is_under(resolved, root_resolved):
                return True
        except Exception:
            continue
    return False


def is_allowed_file_read_path(path: Path) -> tuple[bool, str]:
    reason = deny_reason_for_path(path)
    if reason:
        return False, reason
    if normalize_bool(CONFIG.get("allow_any_vm_file_read", False)):
        return True, ""
    roots = config_path_roots("file_read_roots")
    if roots and is_under_any_root(path, roots):
        return True, ""
    return False, "path_not_in_configured_file_read_roots"


def is_allowed_file_write_path(path: Path) -> tuple[bool, str]:
    reason = deny_reason_for_path(path)
    if reason:
        return False, reason
    if normalize_bool(CONFIG.get("allow_any_vm_file_write", False)):
        return True, ""
    roots = config_path_roots("file_write_roots")
    if roots and is_under_any_root(path, roots):
        return True, ""
    return False, "path_not_in_configured_file_write_roots"


def ensure_file_write_enabled(payload: dict[str, Any], action: str) -> dict[str, Any] | None:
    if not normalize_bool(CONFIG.get("enable_file_write_actions", False)):
        return action_not_enabled(payload, action, reason="file_write_actions_disabled")
    return None


def validate_new_file_name(new_name: str) -> str:
    value = clean_string(new_name)
    if not value:
        return "missing_new_name"
    if value in {".", ".."}:
        return "invalid_new_name"
    if any(ch in value for ch in '<>:"/\\|?*'):
        return "invalid_new_name_reserved_character"
    if value != value.strip(" ."):
        return "invalid_new_name_trailing_space_or_dot"
    return ""

def file_target_path(target: dict[str, Any], key: str, *, base: Path | None = None) -> Path:
    raw = clean_string(target.get(key, ""))
    return resolve_path(raw, base=base or WORKSPACE_ROOT)

def file_open_handle(request_id: str, path: Path, target_type: str) -> str:
    digest = hashlib.sha1(f"{path}|{target_type}|{request_id}|{time.time()}".encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"vm_file_open_{digest}"

def restore_token_for_path(path: Path) -> str:
    digest = hashlib.sha1(f"{path}|{time.time()}|{os.getpid()}".encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"restore_{digest}"

def ensure_shaofu_dirs() -> None:
    for path in (
        SHAOFU_ROOT,
        SHAOFU_FILES_ROOT,
        SHAOFU_APPS_ROOT,
        SHAOFU_FILE_MOVE_TEMP_ROOT,
        SHAOFU_FILE_MOVE_MANIFEST_DIR,
        SHAOFU_FILE_DELETE_ROOT,
        SHAOFU_FILE_DELETE_OBJECTS_DIR,
        SHAOFU_FILE_DELETE_MANIFEST_DIR,
        SHAOFU_FILE_RESTORE_RECORDS_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def shaofu_token(prefix: str, path: Path) -> str:
    digest = hashlib.sha1(
        f"{prefix}|{path}|{time.time()}|{os.getpid()}".encode("utf-8", errors="ignore")
    ).hexdigest()[:16]
    return f"{prefix}_{digest}"


def shaofu_write_json(path: Path, data: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def shaofu_read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None

def is_delete_confirmed(target: dict[str, Any], payload: dict[str, Any]) -> bool:
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}
    return normalize_bool(target.get("confirmed", options.get("confirmed", False)))

def confirm_mode_for_target(target: dict[str, Any], payload: dict[str, Any]) -> str:
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}
    mode = clean_string(target.get("confirm_mode") or options.get("confirm_mode") or "")
    if mode:
        return mode
    return "vm_auto_confirm" if is_delete_confirmed(target, payload) else "none"

def retain_until_for_temp() -> str:
    return "project_close_or_after_3_steps"

def retain_until_for_delete_quarantine() -> str:
    return "manual_restore_or_cleanup_policy"
# ============================================================
# 窗口 / 进程跟踪
# ============================================================
def write_move_temp_manifest(
    *,
    source_path: Path,
    dest_path: Path,
    target_type: str,
    request_id: str,
) -> dict[str, Any]:
    ensure_shaofu_dirs()

    token = shaofu_token("move", source_path)
    manifest = {
        "restore_token": token,
        "action": "file.move",
        "source_path": str(source_path),
        "original_path": str(source_path),
        "dest_path": str(dest_path),
        "target_path": str(dest_path),
        "target_type": target_type,
        "restore_mode": "move_temp",
        "restore_strategy": "move_back",
        "retention_policy": "temp",
        "retain_until": retain_until_for_temp(),
        "expire_on_project_close": True,
        "expire_after_action_count": 3,
        "request_id": request_id,
        "created_at": time.time(),
        "shaofu_domain": "files",
        "shaofu_bucket": "move_temp",
    }

    manifest_path = SHAOFU_FILE_MOVE_MANIFEST_DIR / f"{token}.json"
    shaofu_write_json(manifest_path, manifest)

    return {
        **manifest,
        "manifest_path": str(manifest_path),
    }

def normalize_pid_list(value: Any) -> list[int]:
    if value in (None, "", []):
        return []
    raw_items = value if isinstance(value, list) else [value]
    result: list[int] = []
    seen: set[int] = set()
    for item in raw_items:
        text = clean_string(item)
        if not text:
            continue
        try:
            pid = int(text)
        except Exception:
            continue
        if pid <= 0 or pid in seen:
            continue
        seen.add(pid)
        result.append(pid)
    return result


def register_open_handle(
    *,
    handle: str,
    path: Path,
    target_type: str,
    pids: list[int] | None = None,
    window_title: str = "",
    opener: str = "",
) -> dict[str, Any]:
    normalized_handle = clean_string(handle)
    normalized_pids = normalize_pid_list(pids or [])
    record = {
        "open_handle": normalized_handle,
        "path": str(path),
        "target_path": str(path),
        "target_type": clean_string(target_type) or ("directory" if path.is_dir() else "file"),
        "pids": normalized_pids,
        "pid": normalized_pids[0] if normalized_pids else "",
        "window_title": window_title or path.name,
        "opener": opener,
        "created_at": time.time(),
    }
    if normalized_handle:
        OPEN_HANDLE_REGISTRY[normalized_handle] = record
    return record


def get_open_handle_record(handle: str) -> dict[str, Any] | None:
    normalized_handle = clean_string(handle)
    if not normalized_handle:
        return None
    record = OPEN_HANDLE_REGISTRY.get(normalized_handle)
    return dict(record) if isinstance(record, dict) else None


def unregister_open_handle(handle: str) -> None:
    normalized_handle = clean_string(handle)
    if normalized_handle:
        OPEN_HANDLE_REGISTRY.pop(normalized_handle, None)

def find_open_records_by_path(path: Path, target_type: str = "") -> list[dict[str, Any]]:
    wanted = str(path.resolve(strict=False)).lower()
    kind = clean_string(target_type).lower()
    records: list[dict[str, Any]] = []
    for record in OPEN_HANDLE_REGISTRY.values():
        if str(record.get("path", "")).lower() != wanted:
            continue
        if kind and clean_string(record.get("target_type", "")).lower() != kind:
            continue
        records.append(dict(record))
    return records

def unregister_open_handles_by_path(path: Path, target_type: str = "") -> int:
    """
    按路径清理 OPEN_HANDLE_REGISTRY。

    注意：
    - close 的核心语义不是 open_handle；
    - open_handle 只是内部追踪材料；
    - 当按路径成功关闭窗口后，顺手清理同路径旧记录。
    """
    wanted = str(path.resolve(strict=False)).lower()
    kind = clean_string(target_type).lower()
    removed = 0

    for handle, record in list(OPEN_HANDLE_REGISTRY.items()):
        record_path = str(record.get("path", "") or record.get("target_path", "")).lower()
        record_type = clean_string(record.get("target_type", "")).lower()

        if record_path != wanted:
            continue
        if kind and record_type and record_type != kind:
            continue

        OPEN_HANDLE_REGISTRY.pop(handle, None)
        removed += 1

    return removed

def close_pid(pid: int, *, not_found_is_closed: bool = False) -> dict[str, Any]:
    result = run_command(["taskkill", "/PID", str(int(pid)), "/F"], timeout_sec=DEFAULT_TIMEOUT_SEC)
    not_found = _taskkill_process_not_found(result)
    return {
        "pid": int(pid),
        **result,
        "not_found": not_found,
        "closed": int(result.get("returncode", 1)) == 0 or (not_found_is_closed and not_found),
    }


def ps_json(script: str, *, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> Any:
    result = run_command(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout_sec=timeout_sec,
    )
    if int(result.get("returncode", 1)) != 0:
        return {"ok": False, **result}
    stdout = str(result.get("stdout", "") or "").strip()
    if not stdout:
        return {"ok": True, **result}
    try:
        return json.loads(stdout)
    except Exception:
        return {"ok": True, **result, "raw": stdout}


def find_file_processes_by_path(path: Path) -> list[dict[str, Any]]:
    target = str(path.resolve(strict=False))
    ps = rf"""
$target = {_ps_single_quote(target)}
$selfPid = {os.getpid()}
$items = Get-CimInstance Win32_Process | Where-Object {{
  ($_.ProcessId -ne $selfPid) -and
  ($_.Name -notin @('powershell.exe','pwsh.exe','python.exe','pythonw.exe')) -and
  ($_.CommandLine -and $_.CommandLine -like "*$target*")
}} | Select-Object @{{Name='pid';Expression={{$_.ProcessId}}}},@{{Name='name';Expression={{$_.Name}}}},@{{Name='command_line';Expression={{$_.CommandLine}}}},@{{Name='executable_path';Expression={{$_.ExecutablePath}}}}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        return []
    if isinstance(parsed, dict) and "pid" in parsed:
        parsed = [parsed]
    if not isinstance(parsed, list):
        return []
    result: list[dict[str, Any]] = []
    for item in parsed:
        if isinstance(item, dict):
            result.append({
                "pid": item.get("pid", item.get("ProcessId", "")),
                "name": clean_string(item.get("name", item.get("Name", ""))),
                "command_line": clean_string(item.get("command_line", item.get("CommandLine", ""))),
                "executable_path": clean_string(item.get("executable_path", item.get("ExecutablePath", ""))),
            })
    return result

def _ps_json_array(parsed: Any) -> list[dict[str, Any]]:
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        return []
    if isinstance(parsed, dict) and any(k in parsed for k in ("pid", "hwnd", "window_title")):
        return [parsed]
    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    return []


def find_file_windows_by_title(path: Path) -> list[dict[str, Any]]:
    """
    按窗口标题查找文件窗口。

    这是中文路径和新版 Notepad 的兜底方式：
    - CommandLine 里中文路径可能乱码；
    - 但窗口标题通常会包含文件名，例如 4321.txt。
    """
    filename = path.name
    ps = rf"""
$filename = {_ps_single_quote(filename)}
$selfPid = {os.getpid()}
$items = @()

Get-Process | Where-Object {{
  ($_.Id -ne $selfPid) -and
  ($_.MainWindowHandle -ne 0) -and
  ($_.MainWindowTitle -like "*$filename*") -and
  ($_.ProcessName -notin @('powershell','pwsh','python','pythonw'))
}} | ForEach-Object {{
  $items += [pscustomobject]@{{
    pid = $_.Id
    name = $_.ProcessName
    hwnd = [int64]$_.MainWindowHandle
    window_title = $_.MainWindowTitle
    match_strategy = "window_title"
  }}
}}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    result: list[dict[str, Any]] = []
    for item in _ps_json_array(parsed):
        result.append({
            "pid": item.get("pid", ""),
            "name": clean_string(item.get("name", "")),
            "hwnd": item.get("hwnd", ""),
            "window_title": clean_string(item.get("window_title", "")),
            "match_strategy": "window_title",
        })
    return result


def find_file_windows_by_path_or_title(path: Path) -> list[dict[str, Any]]:
    """
    文件窗口查找总入口。

    第一优先级：CommandLine 包含完整 target_path。
    第二优先级：窗口标题包含文件名。
    """
    result: list[dict[str, Any]] = []
    seen_pids: set[int] = set()

    for item in find_file_processes_by_path(path):
        pids = normalize_pid_list(item.get("pid"))
        if not pids:
            continue
        pid = pids[0]
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        copied = dict(item)
        copied.setdefault("match_strategy", "command_line")
        result.append(copied)

    for item in find_file_windows_by_title(path):
        pids = normalize_pid_list(item.get("pid"))
        if not pids:
            continue
        pid = pids[0]
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        result.append(dict(item))

    return result

def sort_file_close_candidates(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    文件关闭候选排序。
    关闭时必须优先处理有 hwnd 的可见窗口。
    """
    def score(item: dict[str, Any]) -> tuple[int, int, int]:
        hwnds = normalize_pid_list(item.get("hwnd", ""))
        title = clean_string(item.get("window_title", ""))
        strategy = clean_string(item.get("match_strategy", ""))

        has_hwnd = 1 if hwnds else 0
        has_title = 1 if title else 0
        is_title_match = 1 if strategy == "window_title" else 0

        # 分数越高越优先，所以返回时用 reverse=True
        return (has_hwnd, has_title, is_title_match)

    return sorted([dict(item) for item in windows], key=score, reverse=True)

def close_windows_by_hwnd_or_pid(windows: list[dict[str, Any]], *, close_mode: str = "one") -> dict[str, Any]:
    """
    优先向可见窗口发送 WM_CLOSE。

    关键规则：
    - close_mode=one 时，不是取第一个匹配项；
    - 必须优先选择有 hwnd 的真实可见窗口；
    - 没有 hwnd 时才退回 pid。
    """
    ordered = sort_file_close_candidates(windows)
    selected = list(ordered)
    if clean_string(close_mode).lower() != "all" and selected:
        selected = [selected[0]]

    hwnds: list[int] = []
    pids: list[int] = []

    for item in selected:
        for hwnd in normalize_pid_list(item.get("hwnd", "")):
            if hwnd not in hwnds:
                hwnds.append(hwnd)
        for pid in normalize_pid_list(item.get("pid", "")):
            if pid not in pids:
                pids.append(pid)

    ps = rf"""
$hwnds = @({','.join(str(hwnd) for hwnd in hwnds)})
$pids = @({','.join(str(pid) for pid in pids)})

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32CloseHelper {{
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr hWnd);
}}
"@

$WM_CLOSE = 0x0010
$sent = 0
$errors = @()

foreach ($hwnd in $hwnds) {{
  try {{
    $ptr = [IntPtr]::new([int64]$hwnd)
    if ([Win32CloseHelper]::IsWindow($ptr)) {{
      [Win32CloseHelper]::PostMessage($ptr, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
      $sent += 1
    }}
  }} catch {{
    $errors += $_.Exception.Message
  }}
}}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
@{{
  ok = ($sent -gt 0)
  sent_close_count = $sent
  hwnds = $hwnds
  pids = $pids
  selected = $pids
  errors = $errors
}} | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    if isinstance(parsed, dict):
        parsed["selected_windows"] = selected
        parsed["ordered_windows"] = ordered
        return parsed

    return {
        "ok": False,
        "sent_close_count": 0,
        "hwnds": hwnds,
        "pids": pids,
        "selected_windows": selected,
        "ordered_windows": ordered,
        "errors": ["wm_close_result_parse_failed"],
    }


def force_kill_file_window_pids(windows: list[dict[str, Any]], *, close_mode: str = "one") -> list[dict[str, Any]]:
    """
    最后的强制关闭兜底。

    关键规则：
    - 优先结束有 hwnd 的可见窗口所属 pid；
    - close_mode=one 只处理一个真实可见窗口；
    - close_mode=all 才处理所有匹配窗口。
    """
    ordered = sort_file_close_candidates(windows)
    selected = list(ordered)
    if clean_string(close_mode).lower() != "all" and selected:
        selected = [selected[0]]

    pids = normalize_pid_list([item.get("pid") for item in selected])
    return [close_pid(pid, not_found_is_closed=False) for pid in pids]

def explorer_windows_for_path(path: Path) -> dict[str, Any]:
    target = str(path.resolve(strict=False))
    ps = rf"""
$target = {_ps_single_quote(target)}
$items = @()
$shell = New-Object -ComObject Shell.Application
foreach ($w in $shell.Windows()) {{
  try {{
    $location = $w.Document.Folder.Self.Path
    if ($location -eq $target) {{
      $items += [pscustomobject]@{{ hwnd=$w.HWND; location=$location; title=$w.LocationName }}
    }}
  }} catch {{}}
}}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        return {"ok": False, "windows": [], "error": parsed.get("stderr", parsed.get("error", ""))}
    if isinstance(parsed, dict) and "hwnd" in parsed:
        windows = [parsed]
    elif isinstance(parsed, list):
        windows = [item for item in parsed if isinstance(item, dict)]
    else:
        windows = []
    return {"ok": True, "windows": windows, "count": len(windows)}


def activate_explorer_window_for_path(path: Path) -> dict[str, Any]:
    target = str(path.resolve(strict=False))
    ps = rf"""
$target = {_ps_single_quote(target)}
$activated = 0
$shell = New-Object -ComObject Shell.Application
$ws = New-Object -ComObject WScript.Shell
foreach ($w in $shell.Windows()) {{
  try {{
    $location = $w.Document.Folder.Self.Path
    if ($location -eq $target) {{
      $w.Visible = $true
      $null = $ws.AppActivate([int]$w.HWND)
      $activated += 1
      break
    }}
  }} catch {{}}
}}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
@{{ok=$true; activated_count=$activated; target=$target}} | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    return parsed if isinstance(parsed, dict) else {"ok": False, "activated_count": 0}


def close_explorer_windows_for_path(path: Path, *, close_mode: str = "one") -> dict[str, Any]:
    target = str(path.resolve(strict=False))
    mode = "all" if clean_string(close_mode).lower() == "all" else "one"
    ps = rf"""
$target = {_ps_single_quote(target)}
$mode = {_ps_single_quote(mode)}
$closed = 0
$matched = @()
$shell = New-Object -ComObject Shell.Application
foreach ($w in @($shell.Windows())) {{
  try {{
    $location = $w.Document.Folder.Self.Path
    if ($location -eq $target) {{
      $matched += $location
      $w.Quit()
      $closed += 1
      if ($mode -ne 'all') {{ break }}
    }}
  }} catch {{}}
}}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
@{{ok=($closed -gt 0); target=$target; closed_count=$closed; matched_paths=$matched}} | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    if isinstance(parsed, dict):
        return parsed
    return {"ok": False, "target": target, "closed_count": 0, "matched_paths": []}


def activate_file_window_by_path(path: Path) -> dict[str, Any]:
    processes = find_file_processes_by_path(path)
    pids = normalize_pid_list([item.get("pid") for item in processes])
    if not pids:
        return {"ok": False, "activated_count": 0, "pids": []}
    ps = rf"""
$pids = @({','.join(str(pid) for pid in pids)})
$ws = New-Object -ComObject WScript.Shell
$count = 0
foreach ($pid in $pids) {{
  try {{ if ($ws.AppActivate([int]$pid)) {{ $count += 1; break }} }} catch {{}}
}}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
@{{ok=($count -gt 0); activated_count=$count; pids=$pids}} | ConvertTo-Json -Depth 4
"""
    parsed = ps_json(ps, timeout_sec=12)
    return parsed if isinstance(parsed, dict) else {"ok": False, "activated_count": 0, "pids": pids}


def close_file_windows_by_path(path: Path, *, close_mode: str = "one") -> dict[str, Any]:
    """
    按 target_path 关闭文件窗口。

    新规则：
    - 不能只看 taskkill 是否成功；
    - 必须关闭后复查；
    - 复查确认目标文件窗口不存在，才 ok=true。
    """
    mode = "all" if clean_string(close_mode).lower() == "all" else "one"

    before_windows = find_file_windows_by_path_or_title(path)
    before_pids = normalize_pid_list([item.get("pid") for item in before_windows])

    if not before_windows:
        return {
            "ok": False,
            "path": str(path),
            "pids": [],
            "attempts": [],
            "closed_count": 0,
            "processes": [],
            "before_windows": [],
            "after_windows": [],
            "after_pids": [],
            "verified_closed": False,
            "reason": "file_window_not_found_before_close",
        }

    # 第一次：模拟正常关闭窗口。
    wm_close_result = close_windows_by_hwnd_or_pid(before_windows, close_mode=mode)

    time.sleep(1.0)
    after_windows = find_file_windows_by_path_or_title(path)
    after_pids = normalize_pid_list([item.get("pid") for item in after_windows])

    # 如果 WM_CLOSE 后已经没有目标窗口，才算真正成功。
    if not after_windows:
        selected_count = 1 if mode != "all" else len(before_windows)
        return {
            "ok": True,
            "path": str(path),
            "pids": before_pids,
            "attempts": [],
            "closed_count": selected_count,
            "processes": before_windows,
            "before_windows": before_windows,
            "wm_close_result": wm_close_result,
            "after_windows": [],
            "after_pids": [],
            "verified_closed": True,
            "close_method": "wm_close",
        }

    # 第二次：如果普通关闭失败，再强制结束匹配进程。
    kill_attempts = force_kill_file_window_pids(after_windows, close_mode=mode)

    time.sleep(1.0)
    final_windows = find_file_windows_by_path_or_title(path)
    final_pids = normalize_pid_list([item.get("pid") for item in final_windows])

    verified_closed = len(final_windows) == 0
    killed_count = sum(1 for item in kill_attempts if bool(item.get("closed", False)))

    return {
        "ok": verified_closed,
        "path": str(path),
        "pids": before_pids,
        "attempts": kill_attempts,
        "closed_count": killed_count if verified_closed else 0,
        "processes": before_windows,
        "before_windows": before_windows,
        "wm_close_result": wm_close_result,
        "after_windows": after_windows,
        "after_pids": after_pids,
        "final_windows": final_windows,
        "final_pids": final_pids,
        "verified_closed": verified_closed,
        "close_method": "wm_close_then_taskkill" if kill_attempts else "wm_close",
        "reason": "" if verified_closed else "file_window_still_visible_after_close",
    }

# ============================================================
# 文件动作：读 / 打开 / 关闭
# ============================================================

def action_file_list(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    root_id = clean_string(target.get("root_id", default_vm_file_root_id())) or default_vm_file_root_id()
    relative_path = clean_string(target.get("relative_path", ""))
    try:
        result = build_file_list_result(root_id=root_id, relative_path=relative_path)
        return receipt(ok=True, request_id=request_id, action="file.list", message="VM file list executed.", data=result)
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.list", message="VM file list failed.", error=str(exc))


def action_file_inspect(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    try:
        info = resolve_file_action_target(payload)
        path = info["path"]
        allowed, reason = is_allowed_file_read_path(path)
        if not allowed:
            return receipt(ok=False, request_id=request_id, action="file.inspect", message="VM file inspect denied.", error=reason)
        exists = path.exists()
        stat = path.stat() if exists else None
        data = {
            "path": str(path),
            "target_path": str(path),
            "target_type": "directory" if exists and path.is_dir() else str(info.get("target_type", "file") or "file"),
            "root_id": str(info.get("root_id", "")),
            "relative_path": str(info.get("relative_path", "")),
            "exists": exists,
            "is_file": bool(exists and path.is_file()),
            "is_dir": bool(exists and path.is_dir()),
            "size": int(stat.st_size) if stat is not None and path.is_file() else 0,
            "name": path.name,
            "suffix": path.suffix,
            "parent": str(path.parent),
        }
        return receipt(ok=True, request_id=request_id, action="file.inspect", message="VM file inspect executed.", data=data)
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.inspect", message="VM file inspect failed.", error=str(exc))


def action_file_locate(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    try:
        info = resolve_file_action_target(payload)
        path = info["path"]
        allowed, reason = is_allowed_file_read_path(path)
        if not allowed:
            return receipt(ok=False, request_id=request_id, action="file.locate", message="VM file locate denied.", error=reason)
        if not path.exists():
            return receipt(ok=False, request_id=request_id, action="file.locate", message="Target not found.", error=f"not_found: {path}")
        if path.is_dir():
            subprocess.Popen(["explorer.exe", str(path)])
        else:
            subprocess.Popen(["explorer.exe", "/select,", str(path)])
        return receipt(ok=True, request_id=request_id, action="file.locate", message="VM file locate executed.", data={"path": str(path), "folder": str(path if path.is_dir() else path.parent), "target_type": str(info.get("target_type", ""))})
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.locate", message="VM file locate failed.", error=str(exc))


def action_file_open(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    try:
        info = resolve_file_action_target(payload)
        path = info["path"]
        target_type = str(info.get("target_type", "") or "").strip().lower()
        allowed, reason = is_allowed_file_read_path(path)
        if not allowed:
            return receipt(ok=False, request_id=request_id, action="file.open", message="VM file open denied.", error=reason)
        if not path.exists():
            return receipt(ok=False, request_id=request_id, action="file.open", message="Target not found.", error=f"not_found: {path}")

        if path.is_dir() or target_type == "directory":
            target_type = "directory"
            existing = explorer_windows_for_path(path)
            if int(existing.get("count", 0) or 0) > 0:
                activation = activate_explorer_window_for_path(path)
                handle = file_open_handle(request_id, path, target_type)
                record = register_open_handle(handle=handle, path=path, target_type=target_type, pids=[], window_title=path.name, opener="existing_explorer_window")
                return receipt(ok=True, request_id=request_id, action="file.open", message="VM folder window activated.", data={
                    "path": str(path), "target_path": str(path), "target_type": target_type,
                    "open_handle": handle, "pid": "", "pids": [], "window_title": path.name,
                    "opener": "existing_explorer_window", "tracked": True, "already_open": True,
                    "activation": activation, "windows": existing.get("windows", []), "registry_size": len(OPEN_HANDLE_REGISTRY),
                })
            proc = subprocess.Popen(["explorer.exe", str(path)])
            pids = [int(proc.pid)] if getattr(proc, "pid", None) else []
            opener = "explorer.exe"
        else:
            target_type = "file"
            existing_processes = find_file_processes_by_path(path)
            if existing_processes:
                activation = activate_file_window_by_path(path)
                pids = normalize_pid_list([item.get("pid") for item in existing_processes])
                handle = file_open_handle(request_id, path, target_type)
                record = register_open_handle(handle=handle, path=path, target_type=target_type, pids=pids, window_title=path.name, opener="existing_file_window")
                return receipt(ok=True, request_id=request_id, action="file.open", message="VM file window activated.", data={
                    "path": str(path), "target_path": str(path), "target_type": target_type,
                    "open_handle": handle, "pid": record.get("pid", ""), "pids": record.get("pids", []),
                    "window_title": path.name, "opener": "existing_file_window", "tracked": True,
                    "already_open": True, "activation": activation, "processes": existing_processes,
                    "registry_size": len(OPEN_HANDLE_REGISTRY),
                })
            pids: list[int] = []
            if path.suffix.lower() in TEXT_FILE_SUFFIXES:
                proc = subprocess.Popen(["notepad.exe", str(path)])
                if getattr(proc, "pid", None):
                    pids.append(int(proc.pid))
                opener = "notepad.exe"
            else:
                os.startfile(str(path))  # type: ignore[attr-defined]
                opener = "os.startfile"

        handle = file_open_handle(request_id, path, target_type)
        record = register_open_handle(handle=handle, path=path, target_type=target_type, pids=pids, window_title=path.name, opener=opener)
        return receipt(ok=True, request_id=request_id, action="file.open", message="VM file open executed.", data={
            "path": str(path), "target_path": str(path), "target_type": target_type,
            "open_handle": handle, "pid": record.get("pid", ""), "pids": record.get("pids", []),
            "window_title": record.get("window_title", path.name), "opener": opener,
            "tracked": True, "already_open": False, "registry_size": len(OPEN_HANDLE_REGISTRY),
        })
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.open", message="VM file open failed.", error=str(exc))


def action_file_close(payload: dict[str, Any]) -> dict[str, Any]:
    """
    关闭文件/文件夹窗口。

    新固定语义：
    1. close 的核心是 target_path/path；
    2. open_handle 不是必需条件，只能用于补 path 或清理 registry；
    3. folder.close 必须按 Explorer 窗口路径关闭，不能 taskkill explorer.exe；
    4. file.close 第一版按 target_path 查找打开该文件的进程/窗口；
    5. closed_count > 0 才算 ok=true；
    6. 找不到对应窗口时必须 ok=false，不能假成功。
    """
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}

    close_mode = clean_string(target.get("close_mode") or options.get("close_mode") or "one").lower()
    close_mode = "all" if close_mode == "all" else "one"

    open_handle = clean_string(target.get("open_handle", ""))
    target_type = clean_string(target.get("target_type", target.get("object_type", ""))).lower()

    raw_path = (
        clean_string(target.get("path", ""))
        or clean_string(target.get("target_path", ""))
        or clean_string(target.get("source_path", ""))
        or clean_string(target.get("old_path", ""))
        or clean_string(target.get("original_path", ""))
    )

    # open_handle 只允许作为“补 path”的辅助，不作为 close 的核心依据。
    handle_record = get_open_handle_record(open_handle)
    if not raw_path and handle_record is not None:
        raw_path = clean_string(handle_record.get("path", "")) or clean_string(handle_record.get("target_path", ""))

    if not target_type and handle_record is not None:
        target_type = clean_string(handle_record.get("target_type", "")).lower()

    if not raw_path:
        return receipt(
            ok=False,
            request_id=request_id,
            action="file.close",
            message="VM file close failed: missing target_path/path.",
            error="missing_target_path",
            data={
                "open_handle": open_handle,
                "target_type": target_type,
                "close_mode": close_mode,
                "reason": "close_requires_target_path_not_open_handle",
                "registry_size": len(OPEN_HANDLE_REGISTRY),
            },
        )

    try:
        path = resolve_path(raw_path, base=WORKSPACE_ROOT)
    except Exception as exc:
        return receipt(
            ok=False,
            request_id=request_id,
            action="file.close",
            message="VM file close path validation failed.",
            error=str(exc),
            data={
                "open_handle": open_handle,
                "path": raw_path,
                "target_type": target_type,
                "close_mode": close_mode,
                "registry_size": len(OPEN_HANDLE_REGISTRY),
            },
        )

    allowed, reason = is_allowed_file_read_path(path)
    if not allowed:
        return receipt(
            ok=False,
            request_id=request_id,
            action="file.close",
            message="VM file close denied.",
            error=reason,
            data={
                "open_handle": open_handle,
                "path": str(path),
                "target_type": target_type,
                "close_mode": close_mode,
                "registry_size": len(OPEN_HANDLE_REGISTRY),
            },
        )

    if not target_type:
        target_type = "directory" if path.is_dir() else "file"

    # folder.close：只按 Explorer 窗口路径关闭，不允许 taskkill explorer.exe。
    if target_type == "directory" or path.is_dir():
        folder_close = close_explorer_windows_for_path(path, close_mode=close_mode)
        closed_count = int(folder_close.get("closed_count", 0) or 0)

        if closed_count > 0:
            removed_by_path = unregister_open_handles_by_path(path, "directory")
            if open_handle:
                unregister_open_handle(open_handle)

            return receipt(
                ok=True,
                request_id=request_id,
                action="file.close",
                message="VM folder window closed by path.",
                data={
                    "open_handle": open_handle,
                    "path": str(path),
                    "target_path": str(path),
                    "target_type": "directory",
                    "close_mode": close_mode,
                    "closed_count": closed_count,
                    "explorer_window_closed": True,
                    "folder_close": folder_close,
                    "registry_removed_count": removed_by_path,
                    "registry_size": len(OPEN_HANDLE_REGISTRY),
                    "close_semantics": "close_by_target_path",
                },
            )

        return receipt(
            ok=False,
            request_id=request_id,
            action="file.close",
            message="Explorer folder window was not found.",
            error="explorer_window_not_found",
            data={
                "open_handle": open_handle,
                "path": str(path),
                "target_path": str(path),
                "target_type": "directory",
                "close_mode": close_mode,
                "closed_count": 0,
                "folder_close": folder_close,
                "registry_size": len(OPEN_HANDLE_REGISTRY),
                "close_semantics": "close_by_target_path",
            },
        )

    # file.close：第一版按 target_path 查找真正打开该文件的进程/窗口。
    file_close = close_file_windows_by_path(path, close_mode=close_mode)
    verified_closed = bool(file_close.get("verified_closed", False))
    closed_count = int(file_close.get("closed_count", 0) or 0)

    if verified_closed:
        removed_by_path = unregister_open_handles_by_path(path, "file")
        if open_handle:
            unregister_open_handle(open_handle)

        return receipt(
            ok=True,
            request_id=request_id,
            action="file.close",
            message="VM file window closed and verified by path.",
            data={
                "open_handle": open_handle,
                "path": str(path),
                "target_path": str(path),
                "target_type": "file",
                "close_mode": close_mode,
                **file_close,
                "registry_removed_count": removed_by_path,
                "registry_size": len(OPEN_HANDLE_REGISTRY),
                "close_semantics": "close_by_target_path_verified",
            },
        )

    return receipt(
        ok=False,
        request_id=request_id,
        action="file.close",
        message="File window was not closed after verification.",
        error=clean_string(file_close.get("reason", "")) or "file_window_not_closed",
        data={
            "open_handle": open_handle,
            "path": str(path),
            "target_path": str(path),
            "target_type": "file",
            "close_mode": close_mode,
            **file_close,
            "closed_count": 0,
            "registry_size": len(OPEN_HANDLE_REGISTRY),
            "close_semantics": "close_by_target_path_verified",
        },
    )


def action_file_close_all(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    target["close_mode"] = "all"
    payload = {**payload, "target": target}
    return action_file_close(payload)


# ============================================================
# 文件动作：写入 / 变更
# ============================================================

def quarantine_destination(source_path: Path) -> Path:
    ensure_shaofu_dirs()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    token = shaofu_token("delete", source_path)
    suffix = source_path.suffix if source_path.is_file() else ""
    safe_stem = source_path.stem or source_path.name or "object"
    name = f"{safe_stem}_{timestamp}_{token}{suffix}"

    return (SHAOFU_FILE_DELETE_OBJECTS_DIR / name).resolve(strict=False)

def manifest_dir() -> Path:
    ensure_shaofu_dirs()
    return SHAOFU_FILE_DELETE_MANIFEST_DIR
def write_delete_manifest(
    *,
    restore_token: str,
    source_path: Path,
    quarantine_path: Path,
    target_type: str,
    request_id: str = "",
    confirm_mode: str = "",
) -> Path:
    payload = {
        "restore_token": restore_token,
        "action": "file.delete",
        "source_path": str(source_path),
        "original_path": str(source_path),
        "quarantine_path": str(quarantine_path),
        "target_path": str(quarantine_path),
        "target_type": target_type,
        "deleted_at": time.time(),
        "restore_mode": "delete_quarantine",
        "restore_strategy": "move_back_from_quarantine",
        "retention_policy": "quarantine",
        "retain_until": retain_until_for_delete_quarantine(),
        "request_id": request_id,
        "confirm_mode": confirm_mode or "unknown",
        "shaofu_domain": "files",
        "shaofu_bucket": "delete_quarantine",
    }
    path = manifest_dir() / f"{restore_token}.json"
    shaofu_write_json(path, payload)
    return path

def read_restore_manifest(token: str) -> dict[str, Any] | None:
    token = clean_string(token)
    if not token:
        return None

    candidates = [
        SHAOFU_FILE_DELETE_MANIFEST_DIR / f"{token}.json",
        SHAOFU_FILE_MOVE_MANIFEST_DIR / f"{token}.json",
    ]

    for path in candidates:
        data = shaofu_read_json(path)
        if data is not None:
            data["_manifest_path"] = str(path)
            return data

    return None

def action_file_copy(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.copy")
    if blocked is not None:
        return blocked
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    try:
        source_path = file_target_path(target, "source_path")
        dest_path = file_target_path(target, "dest_path")
        if not source_path.exists():
            return receipt(ok=False, request_id=request_id, action="file.copy", message="Source not found.", error=f"not_found: {source_path}")
        source_allowed, source_reason = is_allowed_file_read_path(source_path)
        if not source_allowed:
            return receipt(ok=False, request_id=request_id, action="file.copy", message="Source denied.", error=source_reason)
        dest_allowed, dest_reason = is_allowed_file_write_path(dest_path)
        if not dest_allowed:
            return receipt(ok=False, request_id=request_id, action="file.copy", message="Destination denied.", error=dest_reason)
        if dest_path.exists() and not normalize_bool(target.get("overwrite", False)):
            return receipt(ok=False, request_id=request_id, action="file.copy", message="Destination already exists.", error=f"dest_exists: {dest_path}")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        if source_path.is_dir():
            shutil.copytree(str(source_path), str(dest_path), dirs_exist_ok=normalize_bool(target.get("overwrite", False)))
        else:
            shutil.copy2(str(source_path), str(dest_path))
        return receipt(ok=True, request_id=request_id, action="file.copy", message="VM file copy executed.", data={"source_path": str(source_path), "dest_path": str(dest_path), "target_type": "directory" if source_path.is_dir() else "file"})
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.copy", message="VM file copy failed.", error=str(exc))


def action_file_move(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.move")
    if blocked is not None:
        return blocked

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}

    try:
        source_path = file_target_path(target, "source_path")
        dest_path = file_target_path(target, "dest_path")

        if not source_path.exists():
            return receipt(
                ok=False,
                request_id=request_id,
                action="file.move",
                message="Source not found.",
                error=f"not_found: {source_path}",
            )

        source_allowed, source_reason = is_allowed_file_write_path(source_path)
        if not source_allowed:
            return receipt(ok=False, request_id=request_id, action="file.move", message="Source denied.", error=source_reason)

        dest_allowed, dest_reason = is_allowed_file_write_path(dest_path)
        if not dest_allowed:
            return receipt(ok=False, request_id=request_id, action="file.move", message="Destination denied.", error=dest_reason)

        if dest_path.exists():
            return receipt(
                ok=False,
                request_id=request_id,
                action="file.move",
                message="Destination already exists.",
                error=f"dest_exists: {dest_path}",
            )

        target_type = "directory" if source_path.is_dir() else "file"

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source_path), str(dest_path))

        move_manifest = write_move_temp_manifest(
            source_path=source_path,
            dest_path=dest_path,
            target_type=target_type,
            request_id=request_id,
        )

        return receipt(
            ok=True,
            request_id=request_id,
            action="file.move",
            message="VM file move executed with temporary Shaofu material.",
            data={
                "source_path": str(source_path),
                "dest_path": str(dest_path),
                "old_path": str(source_path),
                "new_path": str(dest_path),
                "target_path": str(dest_path),
                "target_type": target_type,
                "restore_token": move_manifest.get("restore_token", ""),
                "restore_mode": "move_temp",
                "restore_strategy": "move_back",
                "retention_policy": "temp",
                "retain_until": retain_until_for_temp(),
                "shaofu_domain": "files",
                "shaofu_bucket": "move_temp",
                "manifest_path": move_manifest.get("manifest_path", ""),
            },
        )

    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.move", message="VM file move failed.", error=str(exc))
    
def action_file_rename(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.rename")
    if blocked is not None:
        return blocked
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    try:
        info = resolve_file_action_target(payload)
        source_path = info["path"]
        target_type = str(info.get("target_type", "") or "").strip().lower()
        new_name = clean_string(target.get("new_name", ""))
        raw_new_path = clean_string(target.get("new_path", ""))
        if not new_name and raw_new_path:
            new_name = Path(raw_new_path).name
        if not source_path.exists():
            return receipt(ok=False, request_id=request_id, action="file.rename", message="Source not found.", error=f"not_found: {source_path}")
        name_error = validate_new_file_name(new_name)
        if name_error:
            return receipt(ok=False, request_id=request_id, action="file.rename", message="Invalid new_name.", error=name_error)
        source_allowed, source_reason = is_allowed_file_write_path(source_path)
        if not source_allowed:
            return receipt(ok=False, request_id=request_id, action="file.rename", message="Source denied.", error=source_reason)
        dest_path = source_path.with_name(new_name)
        dest_allowed, dest_reason = is_allowed_file_write_path(dest_path)
        if not dest_allowed:
            return receipt(ok=False, request_id=request_id, action="file.rename", message="Destination denied.", error=dest_reason)
        if dest_path.exists():
            return receipt(ok=False, request_id=request_id, action="file.rename", message="Destination already exists.", error=f"dest_exists: {dest_path}")
        source_path.rename(dest_path)
        return receipt(ok=True, request_id=request_id, action="file.rename", message="VM file rename executed.", data={
            "path": str(dest_path), "target_path": str(dest_path), "source_path": str(source_path), "dest_path": str(dest_path),
            "old_path": str(source_path), "new_path": str(dest_path), "old_name": source_path.name, "new_name": new_name,
            "target_type": "directory" if target_type == "directory" or dest_path.is_dir() else "file",
            "root_id": str(info.get("root_id", "")), "relative_path": str(info.get("relative_path", "")),
            "restore_strategy": "rename_back",
        })
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.rename", message="VM file rename failed.", error=str(exc))


def action_file_delete(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.delete")
    if blocked is not None:
        return blocked

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}

    confirmed = is_delete_confirmed(target, payload)
    confirm_mode = confirm_mode_for_target(target, payload)

    if not confirmed:
        return receipt(
            ok=False,
            request_id=request_id,
            action="file.delete",
            message="Delete requires confirmation.",
            error="delete_requires_confirmation",
            data={
                "requires_confirm": True,
                "confirmed": False,
                "confirm_mode": "none",
                "target_path": clean_string(target.get("path", target.get("target_path", ""))),
                "target_type": clean_string(target.get("target_type", target.get("object_type", ""))),
            },
        )

    try:
        source_path = file_target_path(target, "path")
        if not source_path.exists():
            return receipt(
                ok=False,
                request_id=request_id,
                action="file.delete",
                message="Source not found.",
                error=f"not_found: {source_path}",
            )

        source_allowed, source_reason = is_allowed_file_write_path(source_path)
        if not source_allowed:
            return receipt(ok=False, request_id=request_id, action="file.delete", message="Source denied.", error=source_reason)

        target_type = "directory" if source_path.is_dir() else "file"
        token = shaofu_token("delete", source_path)
        dest_path = quarantine_destination(source_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.move(str(source_path), str(dest_path))

        manifest_path = write_delete_manifest(
            restore_token=token,
            source_path=source_path,
            quarantine_path=dest_path,
            target_type=target_type,
            request_id=request_id,
            confirm_mode=confirm_mode,
        )

        return receipt(
            ok=True,
            request_id=request_id,
            action="file.delete",
            message="VM file delete executed as Shaofu quarantine move.",
            data={
                "source_path": str(source_path),
                "old_path": str(source_path),
                "original_path": str(source_path),
                "quarantine_path": str(dest_path),
                "target_path": str(dest_path),
                "target_type": target_type,
                "restore_token": token,
                "restore_mode": "delete_quarantine",
                "restore_strategy": "move_back_from_quarantine",
                "manifest_path": str(manifest_path),
                "requires_confirm": True,
                "confirmed": True,
                "confirm_mode": confirm_mode,
                "retention_policy": "quarantine",
                "retain_until": retain_until_for_delete_quarantine(),
                "shaofu_domain": "files",
                "shaofu_bucket": "delete_quarantine",
            },
        )

    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.delete", message="VM file delete failed.", error=str(exc))

def action_file_restore(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.restore")
    if blocked is not None:
        return blocked

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}

    try:
        token = clean_string(target.get("restore_token", ""))
        manifest = read_restore_manifest(token) if token else None

        restore_mode = (
            clean_string(target.get("restore_mode", ""))
            or clean_string((manifest or {}).get("restore_mode", ""))
            or "delete_quarantine"
        )

        if restore_mode == "move_temp":
            source_current = resolve_path(
                clean_string(target.get("dest_path", ""))
                or clean_string((manifest or {}).get("dest_path", ""))
                or clean_string((manifest or {}).get("target_path", "")),
                base=WORKSPACE_ROOT,
            )
            original_path = resolve_path(
                clean_string(target.get("original_path", ""))
                or clean_string(target.get("source_path", ""))
                or clean_string((manifest or {}).get("original_path", ""))
                or clean_string((manifest or {}).get("source_path", "")),
                base=WORKSPACE_ROOT,
            )

            if not source_current.exists():
                return receipt(
                    ok=False,
                    request_id=request_id,
                    action="file.restore",
                    message="Move restore source not found.",
                    error=f"not_found: {source_current}",
                )

            dest_allowed, dest_reason = is_allowed_file_write_path(original_path)
            if not dest_allowed:
                return receipt(ok=False, request_id=request_id, action="file.restore", message="Restore destination denied.", error=dest_reason)

            if original_path.exists() and not normalize_bool(target.get("overwrite", False)):
                return receipt(
                    ok=False,
                    request_id=request_id,
                    action="file.restore",
                    message="Original path already exists.",
                    error=f"dest_exists: {original_path}",
                )

            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source_current), str(original_path))

            record = {
                "restore_token": token,
                "restore_mode": "move_temp",
                "source_path": str(source_current),
                "restored_path": str(original_path),
                "target_type": "directory" if original_path.is_dir() else "file",
                "restored_at": time.time(),
                "request_id": request_id,
                "shaofu_domain": "files",
                "shaofu_bucket": "restore_records",
            }
            record_path = SHAOFU_FILE_RESTORE_RECORDS_DIR / f"{token or shaofu_token('restore', original_path)}.json"
            shaofu_write_json(record_path, record)

            return receipt(
                ok=True,
                request_id=request_id,
                action="file.restore",
                message="VM move restore executed.",
                data={
                    **record,
                    "path": str(original_path),
                    "target_path": str(original_path),
                    "restore_strategy": "move_back",
                    "record_path": str(record_path),
                },
            )

        quarantine_path = resolve_path(
            clean_string(target.get("quarantine_path", ""))
            or clean_string((manifest or {}).get("quarantine_path", "")),
            base=SHAOFU_FILE_DELETE_OBJECTS_DIR,
        )
        original_path = resolve_path(
            clean_string(target.get("original_path", ""))
            or clean_string(target.get("source_path", ""))
            or clean_string((manifest or {}).get("original_path", "")),
            base=WORKSPACE_ROOT,
        )

        if not quarantine_path.exists():
            return receipt(
                ok=False,
                request_id=request_id,
                action="file.restore",
                message="Quarantine path not found.",
                error=f"not_found: {quarantine_path}",
            )

        dest_allowed, dest_reason = is_allowed_file_write_path(original_path)
        if not dest_allowed:
            return receipt(ok=False, request_id=request_id, action="file.restore", message="Restore destination denied.", error=dest_reason)

        if original_path.exists() and not normalize_bool(target.get("overwrite", False)):
            return receipt(
                ok=False,
                request_id=request_id,
                action="file.restore",
                message="Original path already exists.",
                error=f"dest_exists: {original_path}",
            )

        original_path.parent.mkdir(parents=True, exist_ok=True)
        if original_path.exists():
            if original_path.is_dir():
                shutil.rmtree(str(original_path))
            else:
                original_path.unlink()

        shutil.move(str(quarantine_path), str(original_path))

        record = {
            "restore_token": token,
            "restore_mode": "delete_quarantine",
            "quarantine_path": str(quarantine_path),
            "restored_path": str(original_path),
            "original_path": str(original_path),
            "target_type": "directory" if original_path.is_dir() else "file",
            "restored_at": time.time(),
            "request_id": request_id,
            "shaofu_domain": "files",
            "shaofu_bucket": "restore_records",
        }
        record_path = SHAOFU_FILE_RESTORE_RECORDS_DIR / f"{token or shaofu_token('restore', original_path)}.json"
        shaofu_write_json(record_path, record)

        return receipt(
            ok=True,
            request_id=request_id,
            action="file.restore",
            message="VM file restore executed from Shaofu quarantine.",
            data={
                **record,
                "path": str(original_path),
                "target_path": str(original_path),
                "restore_strategy": "move_back_from_quarantine",
                "record_path": str(record_path),
            },
        )

    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.restore", message="VM file restore failed.", error=str(exc))
    
def action_file_mkdir(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.mkdir")
    if blocked is not None:
        return blocked
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    try:
        path = file_target_path(target, "path")
        allowed, reason = is_allowed_file_write_path(path)
        if not allowed:
            return receipt(ok=False, request_id=request_id, action="file.mkdir", message="Target denied.", error=reason)
        if path.exists() and not path.is_dir():
            return receipt(ok=False, request_id=request_id, action="file.mkdir", message="Target exists and is not directory.", error="target_exists_not_directory")
        path.mkdir(parents=True, exist_ok=True)
        return receipt(ok=True, request_id=request_id, action="file.mkdir", message="VM folder created.", data={"path": str(path), "target_path": str(path), "target_type": "directory"})
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.mkdir", message="VM folder create failed.", error=str(exc))


def action_file_touch(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = ensure_file_write_enabled(payload, "file.touch")
    if blocked is not None:
        return blocked
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    try:
        path = file_target_path(target, "path")
        allowed, reason = is_allowed_file_write_path(path)
        if not allowed:
            return receipt(ok=False, request_id=request_id, action="file.touch", message="Target denied.", error=reason)
        if path.exists() and path.is_dir():
            return receipt(ok=False, request_id=request_id, action="file.touch", message="Target exists and is directory.", error="target_exists_directory")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        return receipt(ok=True, request_id=request_id, action="file.touch", message="VM file created.", data={"path": str(path), "target_path": str(path), "target_type": "file"})
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="file.touch", message="VM file create failed.", error=str(exc))


def action_file_create(payload: dict[str, Any]) -> dict[str, Any]:
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    target_type = clean_string(target.get("target_type", target.get("object_type", "file"))).lower()
    return action_file_mkdir(payload) if target_type == "directory" else action_file_touch(payload)
