# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import Any
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import time
import urllib.parse
import webbrowser

try:
    import winreg  # type: ignore
except Exception:
    winreg = None  # type: ignore

from .cfg import (
    CONFIG, WORKSPACE_ROOT, TEST_ROOT, RUNTIME_ROOT, TEMP_ROOT, DOWNLOADS_ROOT,
    APPS_ROOT, MOVED_ROOT, UPDATES_ROOT, BACKUPS_ROOT, QUARANTINE_ROOT,
    DEFAULT_TIMEOUT_SEC, SCAN_TIMEOUT_SEC, PACKAGE_VERSION, PROTOCOL_VERSION,
)
from .util import (
    action_not_enabled, build_hash, clean_string, deny_reason_for_path,
    expand_path, first_existing, find_first_exe_in_dir, is_running_as_admin,
    is_under, normalize_bool, path_short, process_timeout, receipt,
    resolve_path, run_command, safe_filename, safe_id, _ps_single_quote,
)

def parse_display_icon(value: str) -> str:
    """
    Registry DisplayIcon 常见形式：
    "C:\\Path\\app.exe,0"
    "\"C:\\Path\\app.exe\",0"
    """
    text = clean_string(value)
    if not text:
        return ""

    text = text.strip()
    if text.startswith('"'):
        match = re.match(r'"([^"]+)"', text)
        if match:
            return match.group(1)

    # 去掉 ,0 / ,-1 等 icon index
    if "," in text:
        left = text.split(",", 1)[0].strip()
        if left.lower().endswith((".exe", ".bat", ".cmd", ".com")):
            return left

    return text


def normalize_title_for_group(title: str) -> str:
    """
    用于把“卸载微信 / Uninstall ToDesk”还原成更接近主程序的名字。
    这里只做轻量清洗，不做复杂语义判断。
    """
    text = clean_string(title)
    if not text:
        return ""

    lowered = text.lower()

    # 中文卸载前缀
    for prefix in ("卸载", "删除", "移除"):
        if text.startswith(prefix) and len(text) > len(prefix):
            text = text[len(prefix):].strip()
            break

    # 英文卸载前后缀
    replacements = [
        "uninstall ",
        "uninstaller ",
        "remove ",
        "delete ",
        " uninstall",
        " uninstaller",
        " remover",
    ]

    lowered = text.lower()
    for item in replacements:
        if item in lowered:
            idx = lowered.find(item)
            if idx == 0:
                text = text[len(item):].strip()
            elif idx > 0:
                text = text[:idx].strip()
            lowered = text.lower()

    return text.strip()


def is_uninstaller_record(app: dict[str, Any]) -> bool:
    """
    判断这个扫描结果是不是“卸载器记录”。

    这类记录不应该作为独立软件显示，
    应该合并到同一安装目录下的主程序记录里。
    """
    title = clean_string(app.get("title", app.get("name", ""))).lower()
    path = clean_string(app.get("path", "")).lower()
    target_path = clean_string(app.get("target_path", "")).lower()
    source = clean_string(app.get("source", "")).lower()

    check_path = path or target_path
    file_name = ""
    try:
        if check_path:
            file_name = Path(check_path).name.lower()
    except Exception:
        file_name = ""

    title_hits = (
        "卸载" in title
        or "uninstall" in title
        or "uninstaller" in title
        or "uninst" in title
        or "remove " in title
        or title.startswith("remove")
    )

    file_hits = (
        file_name in {"uninstall.exe", "uninst.exe", "unins000.exe", "unins001.exe"}
        or file_name.startswith("unins")
        or file_name.startswith("uninst")
        or file_name.startswith("uninstall")
    )

    # 桌面/开始菜单快捷方式里经常出现“卸载xxx”
    shortcut_uninstaller = "shortcut" in source and title_hits

    return bool(title_hits or file_hits or shortcut_uninstaller)


def is_system_noise_record(app: dict[str, Any]) -> bool:
    """
    过滤 Windows 系统工具、诊断工具、管理工具。
    这些对象不应该在普通 VM 软件治理区显示。
    注意：fallback_builtin_apps 里的记事本/画图/计算器/浏览器仍然保留。
    """
    source = clean_string(app.get("source", "")).lower()
    title = clean_string(app.get("title", app.get("name", ""))).lower()
    path = clean_string(app.get("path", app.get("target_path", ""))).lower()

    # 兜底内置对象不要过滤
    if source.startswith("fallback_"):
        return False

    blocked_title_keywords = [
        "system information",
        "task manager",
        "voiceaccess",
        "voice access",
        "windows powershell",
        "powershell",
        "windows media player",
        "memory diagnostic",
        "narrator",
        "odbc data source",
        "on-screen keyboard",
        "remote desktop",
        "event viewer",
        "computer management",
        "services",
        "performance monitor",
        "resource monitor",
        "registry editor",
        "command prompt",
        "windows tools",
        "control panel",
    ]

    for keyword in blocked_title_keywords:
        if keyword in title:
            return True

    blocked_file_names = {
        "msinfo32.exe",
        "taskmgr.exe",
        "voiceaccess.exe",
        "powershell.exe",
        "powershell_ise.exe",
        "wmplayer.exe",
        "mdsched.exe",
        "narrator.exe",
        "osk.exe",
        "odbcad32.exe",
        "eventvwr.exe",
        "compmgmt.msc",
        "services.msc",
        "perfmon.exe",
        "resmon.exe",
        "regedit.exe",
        "cmd.exe",
    }

    try:
        file_name = Path(path).name.lower() if path else ""
    except Exception:
        file_name = ""

    if file_name in blocked_file_names:
        return True

    # 从 Windows 系统目录扫描出来的快捷方式，大部分先隐藏
    # 记事本/画图/计算器会由 fallback_builtin_apps 重新加入。
    windows_dirs = [
        r"c:\windows\system32",
        r"c:\windows\syswow64",
        r"c:\windows\systemapps",
    ]

    for root in windows_dirs:
        if path.startswith(root):
            return True

    return False


def app_group_key(app: dict[str, Any]) -> str:
    """
    同一软件的主程序和卸载器应该归为同一组。

    优先：
    1. install_dir
    2. path.parent
    3. 清洗后的 title
    """
    install_dir = clean_string(app.get("install_dir", ""))
    path = clean_string(app.get("path", app.get("target_path", "")))
    title = clean_string(app.get("title", app.get("name", "")))

    if install_dir:
        try:
            return str(Path(expand_path(install_dir)).resolve(strict=False)).lower()
        except Exception:
            return expand_path(install_dir).lower()

    if path:
        try:
            return str(Path(expand_path(path)).parent.resolve(strict=False)).lower()
        except Exception:
            try:
                return str(Path(expand_path(path)).parent).lower()
            except Exception:
                pass

    cleaned_title = normalize_title_for_group(title)
    return cleaned_title.lower() or title.lower()


def close_processes_before_move(target: dict[str, Any]) -> dict[str, Any]:
    names: list[str] = []
    raw_names = target.get("process_names")
    if isinstance(raw_names, list):
        names.extend(clean_string(item) for item in raw_names if clean_string(item))
    process_name = clean_string(target.get("process_name"))
    if process_name:
        names.append(process_name)

    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        normalized = name if name.lower().endswith(".exe") else f"{name}.exe"
        key = normalized.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(normalized)

    attempts: list[dict[str, Any]] = []
    for name in deduped:
        try:
            result = run_command(["taskkill", "/IM", name, "/F"], timeout_sec=8)
            attempts.append({"process_name": name, **result, "not_found": _taskkill_process_not_found(result)})
        except Exception as exc:
            attempts.append({"process_name": name, "returncode": -1, "error": str(exc)})

    close_success = bool(attempts) and all(
        int(item.get("returncode", 1)) == 0 or bool(item.get("not_found", False))
        for item in attempts
    )
    return {
        "close_attempted": bool(deduped),
        "close_success": close_success,
        "close_process_not_found": bool(attempts) and all(bool(item.get("not_found", False)) for item in attempts),
        "close_attempts": attempts,
    }


def _move_keyword_candidates(target: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("title", "name", "target_name", "process_name"):
        value = clean_string(target.get(key))
        if value:
            values.append(value)
    raw_names = target.get("process_names")
    if isinstance(raw_names, list):
        values.extend(clean_string(item) for item in raw_names if clean_string(item))
    for key in ("install_dir", "path", "source_path", "target_path", "launch_target_raw"):
        value = clean_string(target.get(key))
        if not value:
            continue
        values.append(value)
        try:
            path = Path(value)
            values.append(path.name)
            values.append(path.stem)
            if path.parent:
                values.append(path.parent.name)
        except Exception:
            pass

    ignored = {
        "app", "apps", "bin", "common", "exe", "file", "files", "install", "program",
        "program files", "setup", "software", "system32", "uninstall", "update", "windows",
        "x64", "x86",
    }
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        lowered = str(value or "").strip().lower().replace(".exe", "")
        for token in re.findall(r"[a-z0-9][a-z0-9_.-]{2,}", lowered):
            cleaned = token.strip("._-")
            if len(cleaned) < 3 or cleaned in ignored or cleaned in seen:
                continue
            seen.add(cleaned)
            result.append(cleaned)
    return result


def _parse_sc_query_services(text: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in str(text or "").splitlines():
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            current = {"name": stripped.split(":", 1)[1].strip()}
        elif upper.startswith("DISPLAY_NAME:") and current:
            current["display_name"] = stripped.split(":", 1)[1].strip()
    if current:
        services.append(current)
    return services


def _service_already_stopped(result: dict[str, Any]) -> bool:
    text = " ".join([
        str(result.get("stdout", "") or ""),
        str(result.get("stderr", "") or ""),
        str(result.get("error", "") or ""),
    ]).lower()
    return any(marker in text for marker in (
        "1062",
        "has not been started",
        "not been started",
        "not started",
        "\u672a\u542f\u52a8",
        "\u6ca1\u6709\u542f\u52a8",
    ))


def close_services_before_move(target: dict[str, Any]) -> dict[str, Any]:
    keywords = _move_keyword_candidates(target)
    if not keywords:
        return {
            "service_stop_attempted": False,
            "service_stop_success": False,
            "service_stop_attempts": [],
            "service_match_keywords": [],
            "matched_services": [],
        }

    try:
        query = run_command(["sc.exe", "query", "type=", "service", "state=", "all"], timeout_sec=12)
    except Exception as exc:
        return {
            "service_stop_attempted": False,
            "service_stop_success": False,
            "service_stop_attempts": [],
            "service_match_keywords": keywords,
            "matched_services": [],
            "service_query_error": str(exc),
        }

    services = _parse_sc_query_services(str(query.get("stdout", "") or ""))
    matches: list[dict[str, str]] = []
    seen: set[str] = set()
    for service in services:
        name = str(service.get("name", "") or "")
        display_name = str(service.get("display_name", "") or "")
        haystack = f"{name} {display_name}".lower()
        if any(keyword in haystack for keyword in keywords):
            key = name.lower()
            if key and key not in seen:
                seen.add(key)
                matches.append(service)

    attempts: list[dict[str, Any]] = []
    for service in matches[:8]:
        name = str(service.get("name", "") or "").strip()
        if not name:
            continue
        try:
            result = run_command(["sc.exe", "stop", name], timeout_sec=12)
            attempts.append({
                "service_name": name,
                "display_name": service.get("display_name", ""),
                **result,
                "already_stopped": _service_already_stopped(result),
            })
        except Exception as exc:
            attempts.append({
                "service_name": name,
                "display_name": service.get("display_name", ""),
                "returncode": -1,
                "error": str(exc),
            })

    service_stop_success = bool(attempts) and all(
        int(item.get("returncode", 1)) == 0 or bool(item.get("already_stopped", False))
        for item in attempts
    )
    return {
        "service_stop_attempted": bool(attempts),
        "service_stop_success": service_stop_success,
        "service_stop_attempts": attempts,
        "service_match_keywords": keywords,
        "matched_services": matches[:8],
    }


def find_processes_using_path(source_path: Path, *, include_self: bool = False) -> list[dict[str, Any]]:
    source_text = str(source_path)
    if not source_text:
        return []
    ps = rf"""
$source = {_ps_single_quote(source_text)}
$selfPid = {os.getpid()}
$items = Get-CimInstance Win32_Process | Where-Object {{
    ((($_.ExecutablePath) -and ($_.ExecutablePath -like "$source*")) -or
     (($_.CommandLine) -and ($_.CommandLine -like "*$source*"))) -and
    ({str(bool(include_self)).lower()} -or ($_.ProcessId -ne $selfPid))
}} | Select-Object @{{Name='pid';Expression={{$_.ProcessId}}}},@{{Name='name';Expression={{$_.Name}}}},@{{Name='executable_path';Expression={{$_.ExecutablePath}}}},@{{Name='command_line';Expression={{$_.CommandLine}}}}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$items | ConvertTo-Json -Depth 4
"""
    try:
        result = run_command(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            timeout_sec=15,
        )
        if int(result.get("returncode", 1)) != 0:
            return []
        raw = str(result.get("stdout", "") or "").strip()
        if not raw:
            return []
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            return []
        items: list[dict[str, Any]] = []
        for item in parsed:
            if isinstance(item, dict):
                items.append({
                    "pid": item.get("pid", item.get("ProcessId", "")),
                    "name": str(item.get("name", item.get("Name", "")) or ""),
                    "executable_path": str(item.get("executable_path", item.get("ExecutablePath", "")) or ""),
                    "command_line": str(item.get("command_line", item.get("CommandLine", "")) or ""),
                })
        return items
    except Exception:
        return []


def _ci_replace_path(value: str, source_path: Path, final_dest: Path) -> str:
    text = str(value or "")
    source = str(source_path)
    dest = str(final_dest)
    if not source:
        return text
    return re.sub(re.escape(source), lambda _match: dest, text, flags=re.IGNORECASE)


def _contains_path(value: str, source_path: Path) -> bool:
    return str(source_path).lower() in str(value or "").lower()


def _write_json(path: Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def _registry_roots() -> list[tuple[Any, str, str]]:
    if winreg is None:
        return []
    return [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]


def backup_registry_app_paths(source_path: Path, backup_dir: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    fields = (
        "InstallLocation",
        "DisplayIcon",
        "UninstallString",
        "QuietUninstallString",
        "DisplayName",
        "DisplayVersion",
        "Publisher",
    )
    if winreg is not None:
        for root, root_name, base_subkey in _registry_roots():
            try:
                with winreg.OpenKey(root, base_subkey, 0, winreg.KEY_READ) as base_key:
                    index = 0
                    while True:
                        try:
                            child = winreg.EnumKey(base_key, index)
                        except OSError:
                            break
                        index += 1
                        subkey = f"{base_subkey}\\{child}"
                        values: dict[str, dict[str, Any]] = {}
                        matched = False
                        try:
                            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as item_key:
                                for field in fields:
                                    try:
                                        value, value_type = winreg.QueryValueEx(item_key, field)
                                    except OSError:
                                        continue
                                    values[field] = {"value": value, "type": int(value_type)}
                                    if _contains_path(str(value), source_path):
                                        matched = True
                        except OSError:
                            continue
                        if matched:
                            entries.append({"root": root_name, "subkey": subkey, "values": values})
            except OSError:
                continue
    payload = {
        "source_path": str(source_path),
        "registry_entries": entries,
        "registry_backup_count": len(entries),
    }
    payload["registry_backup_path"] = _write_json(backup_dir / "registry_backup.json", payload)
    return payload


def _registry_root_by_name(root_name: str) -> Any:
    if winreg is None:
        return None
    return {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }.get(str(root_name or "").upper())


def update_registry_app_paths(source_path: Path, final_dest: Path, registry_backup: dict[str, Any]) -> dict[str, Any]:
    updated: list[str] = []
    errors: list[dict[str, str]] = []
    if winreg is None:
        return {"updated_registry_keys": updated, "registry_update_errors": [{"error": "winreg_unavailable"}]}
    entries = registry_backup.get("registry_entries", []) if isinstance(registry_backup.get("registry_entries"), list) else []
    for entry in entries:
        root = _registry_root_by_name(str(entry.get("root", "")))
        subkey = str(entry.get("subkey", "") or "")
        values = entry.get("values", {}) if isinstance(entry.get("values"), dict) else {}
        if root is None or not subkey:
            continue
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_SET_VALUE) as key:
                changed = False
                for field in ("InstallLocation", "DisplayIcon", "UninstallString", "QuietUninstallString"):
                    meta = values.get(field) if isinstance(values.get(field), dict) else None
                    if not meta:
                        continue
                    old_value = str(meta.get("value", "") or "")
                    if not _contains_path(old_value, source_path):
                        continue
                    winreg.SetValueEx(key, field, 0, int(meta.get("type", winreg.REG_SZ)), _ci_replace_path(old_value, source_path, final_dest))
                    changed = True
                if changed:
                    updated.append(f"{entry.get('root')}\\{subkey}")
        except Exception as exc:
            errors.append({"key": f"{entry.get('root')}\\{subkey}", "error": str(exc)})
    return {"updated_registry_keys": updated, "registry_update_errors": errors}


def restore_registry_app_paths(registry_backup: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if winreg is None:
        return [{"error": "winreg_unavailable"}]
    entries = registry_backup.get("registry_entries", []) if isinstance(registry_backup.get("registry_entries"), list) else []
    for entry in entries:
        root = _registry_root_by_name(str(entry.get("root", "")))
        subkey = str(entry.get("subkey", "") or "")
        values = entry.get("values", {}) if isinstance(entry.get("values"), dict) else {}
        if root is None or not subkey:
            continue
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_SET_VALUE) as key:
                for field, meta in values.items():
                    if isinstance(meta, dict) and field in {"InstallLocation", "DisplayIcon", "UninstallString", "QuietUninstallString"}:
                        winreg.SetValueEx(key, field, 0, int(meta.get("type", winreg.REG_SZ)), meta.get("value", ""))
        except Exception as exc:
            errors.append({"key": f"{entry.get('root')}\\{subkey}", "error": str(exc)})
    return errors


def _shortcut_roots() -> list[Path]:
    roots = [
        Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs"),
        Path(expand_path(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs")),
        Path(r"C:\Users\Public\Desktop"),
        Path(expand_path(r"%USERPROFILE%\Desktop")),
    ]
    return [root for root in roots if str(root)]


def backup_shortcuts_for_path(source_path: Path, backup_dir: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    shortcuts_dir = backup_dir / "shortcuts"
    shortcuts_dir.mkdir(parents=True, exist_ok=True)
    for root in _shortcut_roots():
        try:
            if not root.exists():
                continue
            for path in root.rglob("*.lnk"):
                ps = (
                    "$s=(New-Object -ComObject WScript.Shell).CreateShortcut("
                    + _ps_single_quote(str(path))
                    + "); [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                    + "ConvertTo-Json @{TargetPath=$s.TargetPath;Arguments=$s.Arguments;WorkingDirectory=$s.WorkingDirectory;IconLocation=$s.IconLocation}"
                )
                result = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout_sec=10)
                if int(result.get("returncode", 1)) != 0:
                    continue
                try:
                    meta = json.loads(str(result.get("stdout", "") or "{}"))
                except Exception:
                    meta = {}
                haystack = " ".join(str(meta.get(key, "") or "") for key in ("TargetPath", "WorkingDirectory", "IconLocation"))
                if _contains_path(haystack, source_path):
                    backup_copy = shortcuts_dir / f"{safe_filename(path.stem)}_{len(entries)}.lnk"
                    try:
                        shutil.copy2(path, backup_copy)
                    except Exception:
                        backup_copy = Path("")
                    entries.append({
                        "shortcut_path": str(path),
                        "backup_copy": str(backup_copy) if str(backup_copy) != "." else "",
                        "target": str(meta.get("TargetPath", "") or ""),
                        "arguments": str(meta.get("Arguments", "") or ""),
                        "working_dir": str(meta.get("WorkingDirectory", "") or ""),
                        "icon": str(meta.get("IconLocation", "") or ""),
                    })
        except Exception:
            continue
    payload = {
        "source_path": str(source_path),
        "shortcut_entries": entries,
        "shortcut_backup_count": len(entries),
        "shortcut_backup_dir": str(shortcuts_dir),
    }
    payload["shortcut_backup_path"] = _write_json(backup_dir / "shortcut_backup.json", payload)
    return payload


def update_shortcuts_for_path(source_path: Path, final_dest: Path, shortcut_backup: dict[str, Any]) -> dict[str, Any]:
    updated: list[str] = []
    errors: list[dict[str, str]] = []
    entries = shortcut_backup.get("shortcut_entries", []) if isinstance(shortcut_backup.get("shortcut_entries"), list) else []
    for entry in entries:
        path = str(entry.get("shortcut_path", "") or "")
        if not path:
            continue
        target = _ci_replace_path(str(entry.get("target", "") or ""), source_path, final_dest)
        working_dir = _ci_replace_path(str(entry.get("working_dir", "") or ""), source_path, final_dest)
        icon = _ci_replace_path(str(entry.get("icon", "") or ""), source_path, final_dest)
        ps = (
            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut(" + _ps_single_quote(path) + ");"
            "$s.TargetPath=" + _ps_single_quote(target) + ";"
            "$s.WorkingDirectory=" + _ps_single_quote(working_dir) + ";"
            "$s.IconLocation=" + _ps_single_quote(icon) + ";"
            "$s.Save()"
        )
        result = run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps], timeout_sec=10)
        if int(result.get("returncode", 1)) == 0:
            updated.append(path)
        else:
            errors.append({"shortcut_path": path, "error": str(result.get("stderr", result.get("stdout", "")) or "")})
    return {"updated_shortcuts": updated, "shortcut_update_errors": errors}


def restore_shortcuts(shortcut_backup: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    entries = shortcut_backup.get("shortcut_entries", []) if isinstance(shortcut_backup.get("shortcut_entries"), list) else []
    for entry in entries:
        source = str(entry.get("backup_copy", "") or "")
        dest = str(entry.get("shortcut_path", "") or "")
        if not source or not dest:
            continue
        try:
            shutil.copy2(source, dest)
        except Exception as exc:
            errors.append({"shortcut_path": dest, "error": str(exc)})
    return errors


def backup_services_for_path(source_path: Path, backup_dir: Path) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    if winreg is not None:
        base_subkey = r"SYSTEM\CurrentControlSet\Services"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_subkey, 0, winreg.KEY_READ) as base_key:
                index = 0
                while True:
                    try:
                        service_name = winreg.EnumKey(base_key, index)
                    except OSError:
                        break
                    index += 1
                    subkey = f"{base_subkey}\\{service_name}"
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ) as service_key:
                            image_path, image_type = winreg.QueryValueEx(service_key, "ImagePath")
                            try:
                                display_name, _display_type = winreg.QueryValueEx(service_key, "DisplayName")
                            except OSError:
                                display_name = service_name
                    except OSError:
                        continue
                    if _contains_path(str(image_path), source_path):
                        entries.append({
                            "service_name": service_name,
                            "display_name": str(display_name or service_name),
                            "subkey": subkey,
                            "image_path": str(image_path),
                            "image_type": int(image_type),
                        })
        except OSError:
            pass
    payload = {
        "source_path": str(source_path),
        "service_entries": entries,
        "service_backup_count": len(entries),
    }
    payload["service_backup_path"] = _write_json(backup_dir / "service_backup.json", payload)
    return payload


def update_services_for_path(source_path: Path, final_dest: Path, service_backup: dict[str, Any]) -> dict[str, Any]:
    updated: list[str] = []
    errors: list[dict[str, str]] = []
    if winreg is None:
        return {"updated_services": updated, "service_update_errors": [{"error": "winreg_unavailable"}]}
    entries = service_backup.get("service_entries", []) if isinstance(service_backup.get("service_entries"), list) else []
    for entry in entries:
        subkey = str(entry.get("subkey", "") or "")
        service_name = str(entry.get("service_name", "") or "")
        if not subkey:
            continue
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(
                    key,
                    "ImagePath",
                    0,
                    int(entry.get("image_type", winreg.REG_EXPAND_SZ)),
                    _ci_replace_path(str(entry.get("image_path", "") or ""), source_path, final_dest),
                )
            updated.append(service_name)
        except Exception as exc:
            errors.append({"service_name": service_name, "error": str(exc)})
    return {"updated_services": updated, "service_update_errors": errors}


def restore_services(service_backup: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[dict[str, str]] = []
    if winreg is None:
        return [{"error": "winreg_unavailable"}]
    entries = service_backup.get("service_entries", []) if isinstance(service_backup.get("service_entries"), list) else []
    for entry in entries:
        subkey = str(entry.get("subkey", "") or "")
        service_name = str(entry.get("service_name", "") or "")
        if not subkey:
            continue
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ImagePath", 0, int(entry.get("image_type", winreg.REG_EXPAND_SZ)), str(entry.get("image_path", "") or ""))
        except Exception as exc:
            errors.append({"service_name": service_name, "error": str(exc)})
    return errors


def robocopy_tree(source_path: Path, final_dest: Path) -> dict[str, Any]:
    final_dest.parent.mkdir(parents=True, exist_ok=True)
    result = run_command(
        ["robocopy", str(source_path), str(final_dest), "/E", "/COPY:DAT", "/DCOPY:DAT", "/R:1", "/W:1"],
        timeout_sec=1800,
    )
    return {**result, "robocopy_success": 0 <= int(result.get("returncode", 16)) <= 7}


def rollback_move_update_paths(
    *,
    source_path: Path,
    final_dest: Path,
    backup_original_path: Path | None,
    registry_backup: dict[str, Any] | None = None,
    shortcut_backup: dict[str, Any] | None = None,
    service_backup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {"rollback_attempted": True, "rollback_completed": False}
    if registry_backup:
        details["registry_restore_errors"] = restore_registry_app_paths(registry_backup)
    if shortcut_backup:
        details["shortcut_restore_errors"] = restore_shortcuts(shortcut_backup)
    if service_backup:
        details["service_restore_errors"] = restore_services(service_backup)
    try:
        if backup_original_path and backup_original_path.exists() and not source_path.exists():
            backup_original_path.rename(source_path)
            details["original_restored"] = True
    except Exception as exc:
        details["original_restore_error"] = str(exc)
    try:
        if final_dest.exists():
            shutil.rmtree(final_dest)
            details["dest_removed"] = True
    except Exception as exc:
        details["dest_remove_error"] = str(exc)
    details["rollback_completed"] = not any(str(key).endswith("_error") for key in details)
    return details


def target_exe_after_relocate(target: dict[str, Any], source_path: Path, final_dest: Path) -> str:
    raw = clean_string(target.get("target_path") or target.get("path") or target.get("launch_target_raw"))
    if raw and _contains_path(raw, source_path):
        candidate = Path(_ci_replace_path(raw, source_path, final_dest))
        if candidate.exists():
            return str(candidate)
    try:
        for path in final_dest.rglob("*.exe"):
            return str(path)
    except Exception:
        return ""
    return ""


def move_error_payload(exc: Exception) -> dict[str, Any]:
    text = str(exc)
    lower_text = text.lower()
    winerror = getattr(exc, "winerror", None)
    access_denied = winerror == 5 or "WinError 5" in text or "Access is denied" in text or "拒绝访问" in text
    path_in_use = (
        winerror == 32
        or "WinError 32" in text
        or "being used by another process" in lower_text
        or "另一个程序正在使用此文件" in text
        or "进程无法访问" in text
    )
    return {
        "exception": text,
        "winerror": winerror,
        "error_category": "source_path_in_use" if path_in_use else ("file_locked_or_access_denied" if access_denied else "move_failed"),
        "possible_file_locked": bool(access_denied or path_in_use),
        "file_access_denied": bool(access_denied),
        "source_path_in_use": bool(path_in_use),
        "requires_user_close": bool(path_in_use),
        "manual_close_required": bool(path_in_use),
    }


def make_app_record(
    *,
    title: str,
    path: str = "",
    install_dir: str = "",
    uninstall_string: str = "",
    quiet_uninstall_string: str = "",
    process_name: str = "",
    publisher: str = "",
    version: str = "",
    source: str = "",
    kind: str = "installed_app",
    shell_entry: str = "",
    locate_entry: str = "",
    icon_text: str = "",
) -> dict[str, Any]:
    title = clean_string(title) or "Unknown App"
    path = expand_path(path)
    install_dir = expand_path(install_dir)
    uninstall_string = clean_string(uninstall_string)
    quiet_uninstall_string = clean_string(quiet_uninstall_string)
    shell_entry = clean_string(shell_entry)

    if not path and install_dir:
        path = find_first_exe_in_dir(install_dir)

    if not install_dir and path:
        try:
            install_dir = str(Path(path).parent)
        except Exception:
            install_dir = ""

    if not process_name and path:
        try:
            process_name = Path(path).name
        except Exception:
            process_name = ""

    identity = "|".join([title.lower(), path.lower(), install_dir.lower(), source.lower()])
    app_id = safe_id(identity)

    can_launch = bool(path and Path(path).exists()) or bool(shell_entry)
    can_locate = bool(path and Path(path).exists()) or bool(install_dir and Path(install_dir).exists()) or bool(shell_entry)
    can_close = bool(process_name)

    # 能卸载：扫描到了卸载命令
    can_uninstall = bool(uninstall_string or quiet_uninstall_string)

    # VM 实际测试阶段允许“已安装软件目录”也显示 move 能力，
    # 是否真正执行仍由 Host 三省六部 + VM 端边界共同决定。
    can_move = False
    try:
        if install_dir:
            install_path = Path(install_dir).resolve(strict=False)
            can_move = (
                is_under(install_path, APPS_ROOT)
                or is_under(install_path, DOWNLOADS_ROOT)
                or is_under(install_path, WORKSPACE_ROOT / "apps")
                or install_path.exists()
            )
    except Exception:
        can_move = False

    # 能更新：第一版只有发现 updater 或 updates_root 中有同名目录才标记
    updater_path = ""
    if install_dir:
        for name in ("update.exe", "updater.exe", "Update.exe", "Updater.exe"):
            candidate = Path(install_dir) / name
            if candidate.exists():
                updater_path = str(candidate.resolve(strict=False))
                break

    update_source_dir = ""
    if install_dir:
        possible = UPDATES_ROOT / Path(install_dir).name
        if possible.exists() and possible.is_dir():
            update_source_dir = str(possible.resolve(strict=False))

    # VM 实测阶段：
    # 只要 install_dir 存在，就允许显示“更新”能力；
    # 真正执行时如果没有 updater_path/update_source_dir，再由 action_app_update 返回明确错误。
    can_update = bool((updater_path or update_source_dir) or install_dir)

    return {
        "app_id": app_id,
        "title": title,
        "name": title,
        "kind": kind,
        "path": path,
        "target_path": path,
        "effective_target_path": path,
        "install_dir": install_dir,
        "uninstall_string": uninstall_string,
        "quiet_uninstall_string": quiet_uninstall_string,
        "updater_path": updater_path,
        "update_source_dir": update_source_dir,
        "shell_entry": shell_entry,
        "locate_entry": locate_entry,
        "process_name": process_name,
        "process_names": [process_name] if process_name else [],
        "publisher": publisher,
        "version": version,
        "source": source,
        "permission_state": "test",
        "effective_permission_state": "test",
        "permission_label": "测试",
        "permission_text": "测试",
        "status_text": "VM测试",
        "status_badge": "VM测试",
        "can_adjust": False,
        "can_locate": can_locate,
        "can_launch": can_launch,
        "can_close": can_close,
        "can_uninstall": can_uninstall,
        "can_move": can_move,
        "can_update": can_update,
        "can_clear": False,
        "can_bind_path": False,
        "platform": "vm",
        "platform_object_type": "vm_app",
        "platform_object_id": app_id,
        "path_short": path_short(path or shell_entry or install_dir),
        "icon_text": icon_text or (title[:1].upper() if title else "VM"),
        "tooltip": (
            f"{title}\n"
            f"来源：{source or '-'}\n"
            f"路径：{path or '-'}\n"
            f"安装目录：{install_dir or '-'}\n"
            f"版本：{version or '-'}\n"
            f"发布者：{publisher or '-'}"
        ),
    }


def scan_registry_uninstall_apps() -> list[dict[str, Any]]:
    if winreg is None:
        return []

    results: list[dict[str, Any]] = []
    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "registry_hklm"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "registry_hklm_wow6432"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "registry_hkcu"),
    ]

    for hive, key_path, source in locations:
        try:
            with winreg.OpenKey(hive, key_path) as root:
                count = winreg.QueryInfoKey(root)[0]
                for index in range(count):
                    try:
                        sub_name = winreg.EnumKey(root, index)
                        with winreg.OpenKey(root, sub_name) as subkey:
                            values: dict[str, str] = {}
                            value_count = winreg.QueryInfoKey(subkey)[1]
                            for value_index in range(value_count):
                                try:
                                    name, value, _typ = winreg.EnumValue(subkey, value_index)
                                    values[str(name)] = str(value)
                                except Exception:
                                    continue

                            title = clean_string(values.get("DisplayName", ""))
                            if not title:
                                continue

                            system_component = clean_string(values.get("SystemComponent", ""))
                            if system_component == "1":
                                continue

                            release_type = clean_string(values.get("ReleaseType", ""))
                            if release_type.lower() in {"security update", "update rollup", "hotfix"}:
                                continue

                            install_dir = clean_string(values.get("InstallLocation", ""))
                            display_icon = parse_display_icon(values.get("DisplayIcon", ""))
                            path = display_icon if display_icon.lower().endswith((".exe", ".bat", ".cmd", ".com")) else ""

                            results.append(make_app_record(
                                title=title,
                                path=path,
                                install_dir=install_dir,
                                uninstall_string=values.get("UninstallString", ""),
                                quiet_uninstall_string=values.get("QuietUninstallString", ""),
                                publisher=values.get("Publisher", ""),
                                version=values.get("DisplayVersion", ""),
                                source=source,
                                kind="installed_app",
                            ))
                    except Exception:
                        continue
        except Exception:
            continue

    return results


def powershell_json(command: str, *, timeout_sec: int = SCAN_TIMEOUT_SEC) -> Any:
    try:
        result = run_command(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            timeout_sec=timeout_sec,
        )
        if int(result.get("returncode", 1)) != 0:
            return None
        stdout = str(result.get("stdout", "") or "").strip()
        if not stdout:
            return None
        return json.loads(stdout)
    except Exception:
        return None


def scan_shortcuts() -> list[dict[str, Any]]:
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    appdata = os.environ.get("APPDATA", "")
    public_desktop = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Desktop"
    user_profile = os.environ.get("USERPROFILE", "")
    user_desktop = Path(user_profile) / "Desktop" if user_profile else Path()

    scan_paths = [
        str(Path(program_data) / r"Microsoft\Windows\Start Menu\Programs"),
        str(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs") if appdata else "",
        str(public_desktop),
        str(user_desktop) if user_profile else "",
    ]
    scan_paths = [p for p in scan_paths if p and Path(p).exists()]

    if not scan_paths:
        return []

    ps_array = "@(" + ",".join("'" + p.replace("'", "''") + "'" for p in scan_paths) + ")"

    command = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$w = New-Object -ComObject WScript.Shell
$paths = {ps_array}
$items = @()
foreach ($p in $paths) {{
  Get-ChildItem -Path $p -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | ForEach-Object {{
    $s = $w.CreateShortcut($_.FullName)
    $items += [pscustomobject]@{{
      name = $_.BaseName
      shortcut = $_.FullName
      target = $s.TargetPath
      arguments = $s.Arguments
      working_dir = $s.WorkingDirectory
      icon = $s.IconLocation
    }}
  }}
}}
$items | ConvertTo-Json -Depth 4
"""

    raw = powershell_json(command)
    if raw is None:
        return []

    entries = raw if isinstance(raw, list) else [raw]
    results: list[dict[str, Any]] = []

    for item in entries:
        if not isinstance(item, dict):
            continue
        title = clean_string(item.get("name", ""))
        target = expand_path(clean_string(item.get("target", "")))
        working_dir = expand_path(clean_string(item.get("working_dir", "")))

        if not title or not target:
            continue

        # 只保留可执行对象或 shell 入口
        kind = "shortcut"
        shell_entry = ""
        path = target

        if target.lower().startswith("shell:"):
            kind = "appx"
            shell_entry = target
            path = ""
        elif not target.lower().endswith((".exe", ".bat", ".cmd", ".com")):
            continue

        results.append(make_app_record(
            title=title,
            path=path,
            install_dir=working_dir,
            process_name=Path(path).name if path else "",
            source="shortcut",
            kind=kind,
            shell_entry=shell_entry,
            locate_entry="shell:AppsFolder" if kind == "appx" else "",
        ))

    return results


def fallback_builtin_apps() -> list[dict[str, Any]]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local_app_data = os.environ.get("LOCALAPPDATA", "")

    return [
        make_app_record(
            title="记事本",
            path=first_existing([
                rf"{system_root}\System32\notepad.exe",
                rf"{system_root}\SysWOW64\notepad.exe",
            ]),
            process_name="notepad.exe",
            source="fallback_builtin",
            kind="local_exe",
            icon_text="记",
        ),
        make_app_record(
            title="Microsoft Edge",
            path=first_existing([
                rf"{program_files_x86}\Microsoft\Edge\Application\msedge.exe",
                rf"{program_files}\Microsoft\Edge\Application\msedge.exe",
                rf"{local_app_data}\Microsoft\Edge\Application\msedge.exe",
            ]),
            process_name="msedge.exe",
            source="fallback_builtin",
            kind="local_exe",
            icon_text="E",
        ),
        make_app_record(
            title="Google Chrome",
            path=first_existing([
                rf"{program_files}\Google\Chrome\Application\chrome.exe",
                rf"{program_files_x86}\Google\Chrome\Application\chrome.exe",
                rf"{local_app_data}\Google\Chrome\Application\chrome.exe",
            ]),
            process_name="chrome.exe",
            source="fallback_builtin",
            kind="local_exe",
            icon_text="C",
        ),
        make_app_record(
            title="计算器",
            kind="appx",
            shell_entry=r"shell:AppsFolder\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App",
            locate_entry="shell:AppsFolder",
            process_name="CalculatorApp.exe",
            source="fallback_appx",
            icon_text="算",
        ),
        make_app_record(
            title="画图",
            kind="appx",
            shell_entry=r"shell:AppsFolder\Microsoft.Paint_8wekyb3d8bbwe!App",
            locate_entry="shell:AppsFolder",
            process_name="mspaint.exe",
            source="fallback_appx",
            icon_text="画",
        ),
    ]


def merge_app_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    合并动态扫描结果。

    目标：
    1. 主程序和卸载器合并。
       ToDesk.exe + uninst.exe -> ToDesk
       Weixin.exe + Uninstall.exe -> 微信

    2. 卸载器不作为独立软件显示。

    3. 过滤 Windows 系统工具，避免 System Information / Task Manager /
       PowerShell / ODBC / Narrator 等暴露在普通软件治理区。
    """
    grouped: dict[str, list[dict[str, Any]]] = {}

    for item in records:
        if is_system_noise_record(item):
            continue

        key = app_group_key(item)
        if not key:
            continue

        grouped.setdefault(key, []).append(item)

    merged: list[dict[str, Any]] = []

    for _key, group in grouped.items():
        if not group:
            continue

        normal_records = [item for item in group if not is_uninstaller_record(item)]
        uninstall_records = [item for item in group if is_uninstaller_record(item)]

        # 优先选择非卸载器作为主记录
        if normal_records:
            main = dict(normal_records[0])
        else:
            # 如果只有卸载器，保留一条“仅卸载器”记录，但不让它看起来像普通启动软件
            main = dict(uninstall_records[0])
            old_title = clean_string(main.get("title", main.get("name", "")))
            cleaned_title = normalize_title_for_group(old_title)

            if cleaned_title:
                main["title"] = cleaned_title
                main["name"] = cleaned_title

            main["kind"] = "uninstaller_only"
            main["can_launch"] = False
            main["can_close"] = False

        # 合并同组普通记录的信息
        for item in normal_records[1:]:
            for field in (
                "publisher",
                "version",
                "install_dir",
                "path",
                "target_path",
                "effective_target_path",
                "process_name",
                "shell_entry",
                "locate_entry",
                "updater_path",
                "update_source_dir",
            ):
                if not main.get(field) and item.get(field):
                    main[field] = item[field]

            for flag in (
                "can_locate",
                "can_launch",
                "can_close",
                "can_move",
                "can_update",
            ):
                main[flag] = bool(main.get(flag, False) or item.get(flag, False))

            if main.get("source") != item.get("source"):
                main["source"] = f"{main.get('source', '')}+{item.get('source', '')}".strip("+")

        # 把卸载器合并进主记录，不单独显示
        for item in uninstall_records:
            uninstall_path = clean_string(item.get("path", item.get("target_path", "")))
            uninstall_string = clean_string(item.get("uninstall_string", ""))
            quiet_uninstall_string = clean_string(item.get("quiet_uninstall_string", ""))

            # 卸载快捷方式时，path 本身通常就是卸载程序
            if not uninstall_string and uninstall_path:
                uninstall_string = uninstall_path

            if quiet_uninstall_string and not main.get("quiet_uninstall_string"):
                main["quiet_uninstall_string"] = quiet_uninstall_string

            if uninstall_string and not main.get("uninstall_string"):
                main["uninstall_string"] = uninstall_string

            # 不允许卸载器覆盖主程序 path
            if not normal_records and uninstall_path and not main.get("path"):
                main["path"] = uninstall_path
                main["target_path"] = uninstall_path
                main["effective_target_path"] = uninstall_path

            main["can_uninstall"] = True

            if main.get("source") != item.get("source"):
                main["source"] = f"{main.get('source', '')}+{item.get('source', '')}".strip("+")

        # 注册表项本身可能已经带卸载命令
        for item in group:
            if item.get("uninstall_string") and not main.get("uninstall_string"):
                main["uninstall_string"] = item.get("uninstall_string")
                main["can_uninstall"] = True

            if item.get("quiet_uninstall_string") and not main.get("quiet_uninstall_string"):
                main["quiet_uninstall_string"] = item.get("quiet_uninstall_string")
                main["can_uninstall"] = True

        # 重新计算 path_short，避免显示 uninstall.exe
        main_path = (
            clean_string(main.get("path"))
            or clean_string(main.get("shell_entry"))
            or clean_string(main.get("install_dir"))
            or clean_string(main.get("uninstall_string"))
        )
        main["path_short"] = path_short(main_path)

        title = clean_string(main.get("title", main.get("name", "")))
        main["tooltip"] = (
            f"{title}\n"
            f"来源：{main.get('source', '-') or '-'}\n"
            f"路径：{main.get('path', '-') or '-'}\n"
            f"安装目录：{main.get('install_dir', '-') or '-'}\n"
            f"卸载命令：{main.get('uninstall_string', '-') or '-'}\n"
            f"版本：{main.get('version', '-') or '-'}\n"
            f"发布者：{main.get('publisher', '-') or '-'}"
        )

        merged.append(main)

    return sorted(merged, key=lambda x: str(x.get("title", "")).lower())


def scan_apps() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if normalize_bool(CONFIG.get("allow_dynamic_app_scan", True)):
        records.extend(scan_registry_uninstall_apps())
        records.extend(scan_shortcuts())

    records.extend(fallback_builtin_apps())
    return merge_app_records(records)


def find_app_by_id(app_id: str) -> dict[str, Any] | None:
    app_id = clean_string(app_id)
    if not app_id:
        return None
    for app in scan_apps():
        if clean_string(app.get("app_id")) == app_id:
            return app
    return None


def action_app_scan(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    started = now_ms()
    apps = scan_apps()
    return receipt(
        ok=True,
        request_id=request_id,
        action="app.scan",
        message="VM dynamic app scan completed.",
        data={
            "apps": apps,
            "count": len(apps),
            "duration_ms": now_ms() - started,
            "hostname": platform.node(),
        },
    )


def action_app_locate(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}

    kind = clean_string(target.get("kind", "local_exe"))
    path = clean_string(target.get("path", target.get("target_path", "")))
    shell_entry = clean_string(target.get("shell_entry", ""))
    locate_entry = clean_string(target.get("locate_entry", ""))

    try:
        if kind == "appx" or shell_entry.startswith("shell:"):
            entry = locate_entry or "shell:AppsFolder"
            subprocess.Popen(["explorer.exe", entry])
            return receipt(
                ok=True,
                request_id=request_id,
                action="app.locate",
                message="VM appx locate executed.",
                data={
                    "kind": kind,
                    "shell_entry": shell_entry,
                    "locate_entry": entry,
                },
            )

        if not path:
            return receipt(
                ok=False,
                request_id=request_id,
                action="app.locate",
                message="Missing target.path.",
                error="missing_path",
            )

        target_path = resolve_path(path)
        if not target_path.exists():
            return receipt(
                ok=False,
                request_id=request_id,
                action="app.locate",
                message="Target path does not exist.",
                error=f"not_found: {target_path}",
                data={"path": str(target_path)},
            )

        subprocess.Popen(["explorer.exe", "/select,", str(target_path)])
        return receipt(
            ok=True,
            request_id=request_id,
            action="app.locate",
            message="VM locate executed.",
            data={"path": str(target_path), "folder": str(target_path.parent)},
        )
    except Exception as exc:
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.locate",
            message="VM locate failed.",
            error=str(exc),
        )


def action_app_launch(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}

    kind = clean_string(target.get("kind", "local_exe"))
    path = clean_string(target.get("path", target.get("target_path", "")))
    shell_entry = clean_string(target.get("shell_entry", ""))

    if normalize_bool(options.get("dry_run", False)):
        return receipt(
            ok=True,
            request_id=request_id,
            action="app.launch",
            message="Dry run accepted.",
            data={"kind": kind, "path": path, "shell_entry": shell_entry},
        )

    try:
        if kind == "appx" or shell_entry.startswith("shell:"):
            if not shell_entry:
                return receipt(
                    ok=False,
                    request_id=request_id,
                    action="app.launch",
                    message="Missing shell_entry for appx.",
                    error="missing_shell_entry",
                )
            subprocess.Popen(["explorer.exe", shell_entry])
            return receipt(
                ok=True,
                request_id=request_id,
                action="app.launch",
                message="VM appx launch executed.",
                data={"kind": kind, "shell_entry": shell_entry},
            )

        if not path:
            return receipt(
                ok=False,
                request_id=request_id,
                action="app.launch",
                message="Missing target.path.",
                error="missing_path",
            )

        target_path = resolve_path(path)
        if not target_path.exists():
            return receipt(
                ok=False,
                request_id=request_id,
                action="app.launch",
                message="Target path does not exist.",
                error=f"not_found: {target_path}",
                data={"path": str(target_path)},
            )

        subprocess.Popen([str(target_path)])
        return receipt(
            ok=True,
            request_id=request_id,
            action="app.launch",
            message="VM launch executed.",
            data={"kind": kind, "path": str(target_path)},
        )
    except Exception as exc:
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.launch",
            message="VM launch failed.",
            error=str(exc),
        )


def action_app_close(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}

    raw_names = target.get("process_names", [])
    process_names: list[str] = []

    if isinstance(raw_names, str):
        process_names.append(raw_names)
    elif isinstance(raw_names, list):
        process_names.extend(str(x or "").strip() for x in raw_names)

    process_name = clean_string(target.get("process_name", ""))
    if process_name:
        process_names.append(process_name)

    process_names = [x for x in dict.fromkeys(process_names) if x]

    if not process_names:
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.close",
            message="Missing process_name/process_names.",
            error="missing_process_name",
        )

    attempts: list[dict[str, Any]] = []
    closed = False

    for name in process_names:
        try:
            result = run_command(
                ["taskkill", "/IM", name, "/F"],
                timeout_sec=process_timeout(options),
            )
            attempts.append({"process_name": name, **result})
            if int(result.get("returncode", 1)) == 0:
                closed = True
        except Exception as exc:
            attempts.append({"process_name": name, "error": str(exc)})

    return receipt(
        ok=closed,
        request_id=request_id,
        action="app.close",
        message="VM close attempted." if closed else "VM close did not find a running process.",
        data={
            "process_names": process_names,
            "attempts": attempts,
        },
        error="" if closed else "process_not_closed",
    )


def action_app_uninstall(payload: dict[str, Any]) -> dict[str, Any]:
    if not normalize_bool(CONFIG.get("enable_app_uninstall", False)):
        return action_not_enabled(payload, "app.uninstall")

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}

    quiet_uninstall_string = clean_string(target.get("quiet_uninstall_string"))
    uninstall_string = clean_string(target.get("uninstall_string") or target.get("command"))
    command = quiet_uninstall_string or uninstall_string

    if not command:
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.uninstall",
            message="Missing uninstall string.",
            error="missing_uninstall_string",
        )

    try:
        if quiet_uninstall_string:
            result = run_command(
                quiet_uninstall_string,
                timeout_sec=process_timeout(options),
                shell=True,
            )
            return receipt(
                ok=int(result.get("returncode", 1)) == 0,
                request_id=request_id,
                action="app.uninstall",
                message="VM quiet uninstall command executed.",
                data={
                    "uninstall_string": quiet_uninstall_string,
                    "quiet_uninstall_string": quiet_uninstall_string,
                    "uninstall_mode": "quiet",
                    "execution_mode": "wait",
                    **result,
                },
                error="" if int(result.get("returncode", 1)) == 0 else str(result.get("stderr", "")),
            )

        process = subprocess.Popen(uninstall_string, shell=True)
        return receipt(
            ok=True,
            request_id=request_id,
            action="app.uninstall",
            message="VM GUI uninstall started. Please confirm in VM.",
            data={
                "uninstall_string": uninstall_string,
                "uninstall_mode": "gui",
                "execution_mode": "spawn",
                "process_spawned": True,
                "requires_user_confirmation": True,
                "action_spawned_pending": True,
                "pid": process.pid,
            },
            status="started",
        )
    except Exception as exc:
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.uninstall",
            message="VM uninstall failed.",
            error=str(exc),
        )


def _path_is_reparse_point(path: Path) -> bool:
    """
    判断路径是否为 junction / symlink / reparse point。
    用于防止已经迁移过的目录被再次迁移。
    """
    try:
        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == -1:
            return False
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False


def action_app_move(payload: dict[str, Any]) -> dict[str, Any]:
    if not normalize_bool(CONFIG.get("enable_app_move", False)):
        return action_not_enabled(payload, "app.move")

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}
    move_mode = clean_string(target.get("move_mode") or options.get("move_mode"))
    if move_mode == "installed_app_relocate":
        return action_app_relocate(payload)
    started = time.monotonic()

    source = clean_string(target.get("install_dir") or target.get("source_path") or target.get("path"))
    dest = clean_string(target.get("dest_path") or target.get("move_target_path"))

    if not source:
        return receipt(ok=False, request_id=request_id, action="app.move", message="Missing source path.", error="missing_source_path")

    source_path = resolve_path(source)
    if not dest:
        dest_path = MOVED_ROOT / source_path.name
    else:
        dest_path = resolve_path(dest)

    reason = deny_reason_for_path(source_path)
    if reason:
        return receipt(ok=False, request_id=request_id, action="app.move", message="Denied by VM minimum boundary.", error=reason)

    close_info = close_processes_before_move(target)
    if close_info.get("close_attempted"):
        time.sleep(1.0)
    service_info = {
        "service_stop_attempted": False,
        "service_stop_success": False,
        "service_stop_attempts": [],
        "service_match_keywords": [],
        "matched_services": [],
    }
    if close_info.get("close_attempted") and not close_info.get("close_success", False):
        initial_close_info = dict(close_info)
        service_info = close_services_before_move(target)
        if service_info.get("service_stop_attempted"):
            time.sleep(1.0)
        retry_close_info = close_processes_before_move(target)
        close_info = {
            **retry_close_info,
            "initial_close": initial_close_info,
            "retry_close": retry_close_info,
            "close_attempts": list(initial_close_info.get("close_attempts", [])) + list(retry_close_info.get("close_attempts", [])),
        }

    dest_parent_exists = dest_path.parent.exists()
    common_data = {
        "source_path": str(source_path),
        "dest_path": str(dest_path),
        "source_is_dir": source_path.is_dir(),
        "dest_parent_exists": dest_parent_exists,
        **close_info,
        **service_info,
    }

    if close_info.get("close_attempted") and not close_info.get("close_success", False):
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.move",
            message="VM app move blocked because related process could not be closed.",
            data={
                **common_data,
                "possible_file_locked": True,
                "action_blocked_before_move": True,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
            error="process_close_failed",
        )

    if service_info.get("service_stop_attempted") and not service_info.get("service_stop_success", False):
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.move",
            message="VM app move blocked because related service could not be stopped.",
            data={
                **common_data,
                "possible_file_locked": True,
                "action_blocked_before_move": True,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
            error="service_stop_failed",
        )

    if not source_path.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.move",
            message="Source path does not exist.",
            data={**common_data, "duration_ms": round((time.monotonic() - started) * 1000, 2)},
            error="missing_source_path",
        )

    if dest_path.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.move",
            message="Destination already exists.",
            data={
                **common_data,
                "destination_collision": True,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
            error="destination_exists",
        )

    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source_path), str(dest_path))
        return receipt(
            ok=True,
            request_id=request_id,
            action="app.move",
            message="VM app move executed.",
            data={**common_data, "duration_ms": round((time.monotonic() - started) * 1000, 2)},
        )
    except Exception as exc:
        error_data = move_error_payload(exc)
        return receipt(
            ok=False,
            request_id=request_id,
            action="app.move",
            message="VM app move failed.",
            data={**common_data, **error_data, "duration_ms": round((time.monotonic() - started) * 1000, 2)},
            error=str(error_data.get("error_category", "move_failed")),
        )


def _backup_path_for_original(source_path: Path) -> Path:
    suffix = time.strftime("%Y%m%d_%H%M%S")
    return source_path.with_name(f"{source_path.name}.__backup_{suffix}")


def _remove_incomplete_destination(path: Path) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(str(path), ignore_errors=True)
        elif path.exists():
            path.unlink()
    except Exception:
        pass


def _restore_original_after_failed_junction(source_path: Path, backup_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "rollback_attempted": True,
        "rollback_completed": False,
        "rollback_failed": False,
    }
    try:
        if source_path.exists():
            result["rollback_failed"] = True
            result["rollback_error"] = "source_path_exists_during_rollback"
            return result
        backup_path.rename(source_path)
        result["rollback_completed"] = True
        return result
    except Exception as exc:
        result["rollback_failed"] = True
        result["rollback_error"] = str(exc)
        return result


def _relocate_common_data(
    *,
    source_path: Path,
    dest_path: Path,
    backup_original_path: Path | None,
    started: float,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "source_path": str(source_path),
        "dest_path": str(dest_path),
        "backup_original_path": str(backup_original_path or ""),
        "junction_path": str(source_path),
        "move_mode": "installed_app_relocate",
        "relocate_strategy": "copy_junction",
        "restore_strategy": "remove_junction_restore_original",
        "rollback_strategy": "delete_dest_restore_backup",
        "relocate_status": "preflight_started",
        "source_is_dir": source_path.is_dir(),
        "dest_parent_exists": dest_path.parent.exists(),
        "source_under_program_files": str(source_path).lower().startswith(
            (r"c:\program files", r"c:\program files (x86)")
        ),
        "installed_app_source_allowed": _is_allowed_installed_app_source(source_path),
        "is_admin_required": True,
        "is_admin": is_running_as_admin(),
        "path_namespace": "vm_windows",
        "execution_backend": "vm",
        "target_environment": "virtual_machine",
        "agent_id": "desktop_vm_agent",
        "machine_id": platform.node(),
        "package_version": PACKAGE_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "build_hash": build_hash(),
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }
    if extra:
        payload.update(extra)
    return payload


def _backup_original_path_for_move_update(source_path: Path) -> Path:
    suffix = time.strftime("%Y%m%d_%H%M%S")
    return source_path.with_name(f"{source_path.name}.__backup_{suffix}")


def _relocate_base_data(
    *,
    source_path: Path,
    final_dest: Path,
    selected_root: str,
    backup_original_path: Path | None,
    started: float,
    relocate_target_mode: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = {
        "relocate_strategy": "move_update_paths",
        "relocate_target_mode": relocate_target_mode,
        "relocate_status": "preflight_started",
        "source_path": str(source_path),
        "selected_root": selected_root,
        "dest_path": str(final_dest),
        "final_app_dir": str(final_dest),
        "backup_original_path": str(backup_original_path or ""),
        "move_mode": "installed_app_relocate",
        "restore_strategy": "restore_paths_and_move_back",
        "rollback_strategy": "restore_registry_shortcuts_services_and_move_back",
        "retention_class": "critical_long",
        "cleanup_policy": "never_until_verified",
        "path_namespace": "vm_windows",
        "execution_backend": "vm",
        "target_environment": "virtual_machine",
        "agent_id": "desktop_vm_agent",
        "machine_id": platform.node(),
        "package_version": PACKAGE_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "build_hash": build_hash(),
        "is_admin": is_running_as_admin(),
        "duration_ms": round((time.monotonic() - started) * 1000, 2),
    }
    if extra:
        data.update(extra)
    return data


def _resolve_relocate_destination(
    *,
    source_path: Path,
    target: dict[str, Any],
    options: dict[str, Any],
    relocate_target_mode: str,
) -> tuple[Path | None, str, str]:
    dest_text = clean_string(
        target.get("dest_path")
        or target.get("move_target_path")
        or target.get("dest")
        or options.get("dest_path")
        or options.get("move_target_path")
    )
    selected_root = ""
    if dest_text:
        raw_dest = resolve_path(dest_text)
        final_dest = raw_dest if raw_dest.name.lower() == source_path.name.lower() else raw_dest / source_path.name
        selected_root = str(final_dest.parent)
        return final_dest, selected_root, ""
    if relocate_target_mode == "vm_folder_dialog":
        moved_root = Path(str(CONFIG.get("moved_root") or str(MOVED_ROOT))).expanduser().resolve(strict=False)
        moved_root.mkdir(parents=True, exist_ok=True)
        selected_root = select_vm_folder_via_dialog(
            title=f"请选择 {source_path.name or '软件'} 的迁移目标父目录",
            initial_dir=str(moved_root),
        )
        if not selected_root:
            return None, "", "user_cancelled_dest_path"
        root_path = Path(selected_root).expanduser().resolve(strict=False)
        return root_path / source_path.name, str(root_path), ""
    if relocate_target_mode == "auto_default":
        root_path = Path(str(CONFIG.get("moved_root") or str(MOVED_ROOT))).expanduser().resolve(strict=False)
        return root_path / source_path.name, str(root_path), ""
    return None, "", "missing_dest_path"


def action_app_relocate_move_update_paths(
    payload: dict[str, Any],
    *,
    request_id: str,
    action: str,
    target: dict[str, Any],
    options: dict[str, Any],
    source: str,
    relocate_target_mode: str,
    started: float,
) -> dict[str, Any]:
    if not source:
        return receipt(ok=False, request_id=request_id, action=action, message="Missing source path.", error="missing_source_path")

    source_path = resolve_path(source)
    final_dest, selected_root, dest_error = _resolve_relocate_destination(
        source_path=source_path,
        target=target,
        options=options,
        relocate_target_mode=relocate_target_mode,
    )
    backup_original_path = _backup_original_path_for_move_update(source_path)
    if final_dest is None:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM folder selection cancelled." if dest_error == "user_cancelled_dest_path" else "Missing destination path.",
            error=dest_error,
            data=_relocate_base_data(
                source_path=source_path,
                final_dest=source_path,
                selected_root=selected_root,
                backup_original_path=backup_original_path,
                started=started,
                relocate_target_mode=relocate_target_mode,
                extra={"relocate_status": "cancelled" if dest_error == "user_cancelled_dest_path" else "preflight_failed"},
            ),
        )

    try:
        if source_path.resolve(strict=False) == final_dest.resolve(strict=False) or is_under(source_path, final_dest):
            return receipt(
                ok=False,
                request_id=request_id,
                action=action,
                message="This app appears to be already at the selected destination.",
                error="already_relocated",
                data=_relocate_base_data(
                    source_path=source_path,
                    final_dest=final_dest,
                    selected_root=selected_root,
                    backup_original_path=backup_original_path,
                    started=started,
                    relocate_target_mode=relocate_target_mode,
                    extra={"relocate_status": "already_relocated"},
                ),
            )
    except Exception:
        pass

    base = {
        "source_path": source_path,
        "final_dest": final_dest,
        "selected_root": selected_root,
        "backup_original_path": backup_original_path,
        "started": started,
        "relocate_target_mode": relocate_target_mode,
    }

    if not is_running_as_admin():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Installed app relocation requires elevated VM Agent.",
            error="admin_required",
            data=_relocate_base_data(**base, extra={"relocate_status": "preflight_failed", "error_category": "admin_required"}),
        )
    if not source_path.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Source path does not exist.",
            error="missing_source_path",
            data=_relocate_base_data(**base, extra={"relocate_status": "preflight_failed", "error_category": "missing_source_path"}),
        )
    try:
        if _path_is_reparse_point(source_path):
            return receipt(
                ok=False,
                request_id=request_id,
                action=action,
                message="This app path is a junction/reparse point and appears to be already relocated.",
                error="source_is_reparse_point",
                data=_relocate_base_data(**base, extra={"relocate_status": "already_relocated"}),
            )
    except Exception:
        pass
    source_reason = deny_reason_for_app_relocate_source(source_path)
    if source_reason:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Denied by VM minimum boundary.",
            error=source_reason,
            data=_relocate_base_data(**base, extra={"relocate_status": "preflight_failed", "error_category": "path_denied"}),
        )
    dest_reason = deny_reason_for_path(final_dest)
    if dest_reason:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Destination denied by VM minimum boundary.",
            error=dest_reason,
            data=_relocate_base_data(**base, extra={"relocate_status": "preflight_failed", "error_category": "path_denied"}),
        )
    if final_dest.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Destination already exists.",
            error="destination_exists",
            data=_relocate_base_data(**base, extra={"relocate_status": "preflight_failed", "error_category": "destination_exists"}),
        )

    close_info = close_processes_before_move(target)
    if close_info.get("close_attempted") and not close_info.get("close_success", False):
        service_info = close_services_before_move(target)
        time.sleep(1.0)
        retry_close_info = close_processes_before_move(target)
        close_info = {**close_info, "retry_close_attempts": retry_close_info.get("close_attempts", []), **service_info}
        if retry_close_info.get("close_attempted") and not retry_close_info.get("close_success", False):
            return receipt(
                ok=False,
                request_id=request_id,
                action=action,
                message="VM app relocation blocked because related process could not be closed.",
                error="process_close_failed",
                data=_relocate_base_data(**base, extra={**close_info, "process_stop_attempts": close_info.get("close_attempts", []), "relocate_status": "preflight_failed", "error_category": "process_close_failed"}),
            )
    else:
        service_info = close_services_before_move(target)
        close_info = {**close_info, **service_info}
    if close_info.get("service_stop_attempted") and not close_info.get("service_stop_success", False):
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM app relocation blocked because related service could not be stopped.",
            error="service_stop_failed",
            data=_relocate_base_data(**base, extra={**close_info, "process_stop_attempts": close_info.get("close_attempts", []), "relocate_status": "preflight_failed", "error_category": "service_stop_failed"}),
        )

    running_processes = find_processes_using_path(source_path)
    if running_processes:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="检测到软件仍在后台运行，请在虚拟机中完全退出后重试。",
            error="process_path_still_in_use",
            data=_relocate_base_data(
                **base,
                extra={
                    **close_info,
                    "relocate_status": "preflight_failed",
                    "error_category": "process_path_still_in_use",
                    "requires_user_close": True,
                    "manual_close_required": True,
                    "running_processes": running_processes,
                    "process_stop_attempts": close_info.get("close_attempts", []),
                    "service_stop_attempts": close_info.get("service_stop_attempts", []),
                },
            ),
        )

    backup_dir = BACKUPS_ROOT / f"relocate_{safe_filename(source_path.name)}_{time.strftime('%Y%m%d_%H%M%S')}_{request_id[-8:]}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    registry_backup = backup_registry_app_paths(source_path, backup_dir)
    shortcut_backup = backup_shortcuts_for_path(source_path, backup_dir)
    service_backup = backup_services_for_path(source_path, backup_dir)

    try:
        source_path.rename(backup_original_path)
    except Exception as exc:
        error_data = move_error_payload(exc)
        in_use = bool(error_data.get("source_path_in_use", False))
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="检测到软件仍在后台运行，请在虚拟机中完全退出后重试。" if in_use else "Original app directory could not be renamed to backup.",
            error="source_path_in_use" if in_use else "original_rename_failed",
            data=_relocate_base_data(
                **base,
                extra={
                    **close_info,
                    **error_data,
                    **registry_backup,
                    **shortcut_backup,
                    **service_backup,
                    "relocate_status": "original_rename_failed",
                    "error_category": "source_path_in_use" if in_use else "original_rename_failed",
                    "original_rename_failed": True,
                    "requires_user_close": bool(in_use),
                    "manual_close_required": bool(in_use),
                },
            ),
        )

    copy_result = robocopy_tree(backup_original_path, final_dest)
    if not copy_result.get("robocopy_success", False) or not final_dest.exists():
        rollback = rollback_move_update_paths(
            source_path=source_path,
            final_dest=final_dest,
            backup_original_path=backup_original_path,
            registry_backup=registry_backup,
            shortcut_backup=shortcut_backup,
            service_backup=service_backup,
        )
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Copy to relocation destination failed; rollback was attempted.",
            error="copy_failed",
            data=_relocate_base_data(**base, extra={**close_info, **copy_result, **registry_backup, **shortcut_backup, **service_backup, **rollback, "relocate_status": "copy_failed", "error_category": "copy_failed"}),
        )

    registry_update = update_registry_app_paths(source_path, final_dest, registry_backup)
    if registry_update.get("registry_update_errors"):
        rollback = rollback_move_update_paths(source_path=source_path, final_dest=final_dest, backup_original_path=backup_original_path, registry_backup=registry_backup, shortcut_backup=shortcut_backup, service_backup=service_backup)
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Registry path update failed; relocation was rolled back.",
            error="registry_update_failed",
            data=_relocate_base_data(**base, extra={**close_info, **registry_backup, **shortcut_backup, **service_backup, **registry_update, **rollback, "relocate_status": "rollback_completed" if rollback.get("rollback_completed") else "rollback_failed", "error_category": "registry_update_failed"}),
        )

    service_update = update_services_for_path(source_path, final_dest, service_backup)
    if service_backup.get("service_entries") and service_update.get("service_update_errors"):
        rollback = rollback_move_update_paths(source_path=source_path, final_dest=final_dest, backup_original_path=backup_original_path, registry_backup=registry_backup, shortcut_backup=shortcut_backup, service_backup=service_backup)
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Service ImagePath update failed; relocation was rolled back.",
            error="service_update_failed",
            data=_relocate_base_data(**base, extra={**close_info, **registry_backup, **shortcut_backup, **service_backup, **registry_update, **service_update, **rollback, "relocate_status": "rollback_completed" if rollback.get("rollback_completed") else "rollback_failed", "error_category": "service_update_failed"}),
        )

    shortcut_update = update_shortcuts_for_path(source_path, final_dest, shortcut_backup)
    target_exe = target_exe_after_relocate(target, source_path, final_dest)
    verify_status = "path_verified" if final_dest.exists() and (not target_exe or Path(target_exe).exists()) else "unverified"
    path_update_summary = {
        "registry_updated": len(registry_update.get("updated_registry_keys", [])),
        "shortcuts_updated": len(shortcut_update.get("updated_shortcuts", [])),
        "services_updated": len(service_update.get("updated_services", [])),
        "shortcut_partial": bool(shortcut_update.get("shortcut_update_errors")),
    }
    return receipt(
        ok=True,
        request_id=request_id,
        action=action,
        message="VM app relocation completed with move_update_paths.",
        data=_relocate_base_data(
            **base,
            extra={
                **close_info,
                **registry_backup,
                **shortcut_backup,
                **service_backup,
                **registry_update,
                **shortcut_update,
                **service_update,
                "process_stop_attempts": close_info.get("close_attempts", []),
                "target_exe": target_exe,
                "launch_verified": False,
                "verify_status": verify_status,
                "restore_status": "pending",
                "path_update_summary": path_update_summary,
                "relocate_status": "completed",
            },
        ),
    )


def action_app_relocate(payload: dict[str, Any]) -> dict[str, Any]:
    if not normalize_bool(CONFIG.get("enable_app_move", False)):
        return action_not_enabled(payload, "app.relocate")

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    action = clean_string(payload.get("action")) or "app.relocate"
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}
    started = time.monotonic()

    source = clean_string(
        target.get("install_dir")
        or target.get("source_path")
        or target.get("path")
        or options.get("source_path")
    )
    relocate_strategy = clean_string(
        target.get("relocate_strategy")
        or options.get("relocate_strategy")
        or "move_update_paths"
    )
    relocate_target_mode = clean_string(
        target.get("relocate_target_mode")
        or options.get("relocate_target_mode")
        or "vm_folder_dialog"
    )

    if relocate_strategy == "move_update_paths":
        return action_app_relocate_move_update_paths(
            payload,
            request_id=request_id,
            action=action,
            target=target,
            options=options,
            source=source,
            relocate_target_mode=relocate_target_mode,
            started=started,
        )

    if not source:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Missing source path.",
            error="missing_source_path",
        )

    source_path = resolve_path(source)

    # ------------------------------------------------------------
    # 防止重复迁移
    # 已经迁移到 moved_root 下的目录，不能再次迁移。
    # junction / reparse point 也不应该再次迁移。
    # ------------------------------------------------------------
    moved_root = Path(str(CONFIG.get("moved_root") or str(MOVED_ROOT))).expanduser().resolve(strict=False)

    try:
        if is_under(source_path.resolve(strict=False), moved_root):
            return receipt(
                ok=False,
                request_id=request_id,
                action=action,
                message="This app appears to be already relocated under moved_root.",
                error="source_already_in_moved_root",
                data={
                    "source_path": str(source_path),
                    "moved_root": str(moved_root),
                    "relocate_status": "already_relocated",
                    "move_mode": "installed_app_relocate",
                    "relocate_strategy": "copy_junction",
                    "path_namespace": "vm_windows",
                    "execution_backend": "vm",
                    "target_environment": "virtual_machine",
                },
            )
    except Exception:
        pass

    try:
        if _path_is_reparse_point(source_path):
            return receipt(
                ok=False,
                request_id=request_id,
                action=action,
                message="This app path is a junction/reparse point and appears to be already relocated.",
                error="source_is_reparse_point",
                data={
                    "source_path": str(source_path),
                    "relocate_status": "already_relocated",
                    "move_mode": "installed_app_relocate",
                    "relocate_strategy": "copy_junction",
                    "path_namespace": "vm_windows",
                    "execution_backend": "vm",
                    "target_environment": "virtual_machine",
                },
            )
    except Exception:
        pass

    # ------------------------------------------------------------
    # 迁移目标模式
    #
    # explicit_path:
    #   已经传入 dest_path，直接使用。
    #
    # vm_folder_dialog:
    #   没有 dest_path 时，在 VM 内弹出文件夹选择窗口。
    #   用户选择的是“目标父目录”，系统会在里面创建 软件名_时间戳。
    #
    # auto_default:
    #   测试兜底模式，自动使用 CONFIG["moved_root"]。
    # ------------------------------------------------------------
    dest_path_text = clean_string(
        target.get("dest_path")
        or target.get("move_target_path")
        or target.get("dest")
        or options.get("dest_path")
        or options.get("move_target_path")
    )

    if dest_path_text:
        dest_path = resolve_path(dest_path_text)

    elif relocate_target_mode == "vm_folder_dialog":
        moved_root.mkdir(parents=True, exist_ok=True)

        selected_root = select_vm_folder_via_dialog(
            title=f"请选择 {source_path.name or '软件'} 的迁移目标文件夹",
            initial_dir=str(moved_root),
        )

        if not selected_root:
            return receipt(
                ok=False,
                request_id=request_id,
                action=action,
                message="VM folder selection cancelled.",
                error="user_cancelled_dest_path",
                data={
                    "source_path": str(source_path),
                    "relocate_target_mode": "vm_folder_dialog",
                    "relocate_status": "cancelled",
                    "move_mode": "installed_app_relocate",
                    "relocate_strategy": "copy_junction",
                    "path_namespace": "vm_windows",
                    "execution_backend": "vm",
                    "target_environment": "virtual_machine",
                },
            )

        suffix = time.strftime("%Y%m%d_%H%M%S")
        dest_path = (
            Path(selected_root).expanduser().resolve(strict=False)
            / f"{safe_filename(source_path.name or 'app')}_{suffix}"
        )

    elif relocate_target_mode == "auto_default":
        moved_root.mkdir(parents=True, exist_ok=True)
        suffix = time.strftime("%Y%m%d_%H%M%S")
        dest_path = moved_root / f"{safe_filename(source_path.name or 'app')}_{suffix}"

    else:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Missing destination path.",
            error="missing_dest_path",
            data={
                "source_path": str(source_path),
                "relocate_target_mode": relocate_target_mode,
                "relocate_status": "preflight_failed",
            },
        )

    backup_original_path = _backup_path_for_original(source_path)

    source_reason = deny_reason_for_app_relocate_source(source_path)
    if source_reason:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Denied by VM minimum boundary.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "error_category": "path_denied",
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error=source_reason,
        )

    dest_reason = deny_reason_for_path(dest_path)
    if dest_reason:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Destination denied by VM minimum boundary.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "error_category": "path_denied",
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error=dest_reason,
        )

    if dest_path.anchor and not Path(dest_path.anchor).exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Destination drive does not exist in VM.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "error_category": "dest_drive_missing",
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="dest_drive_missing",
        )

    if not source_path.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Source path does not exist.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="missing_source_path",
        )

    if not source_path.is_dir():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Installed app relocation requires a source directory.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="source_not_directory",
        )

    if dest_path.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Destination already exists.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "destination_collision": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="destination_exists",
        )

    if backup_original_path.exists():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Backup original path already exists.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "backup_collision": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="backup_path_exists",
        )

    if not is_running_as_admin():
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="Installed app relocation requires an elevated VM Agent.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    "relocate_status": "preflight_failed",
                    "admin_required": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="admin_required",
        )

    close_info = close_processes_before_move(target)
    if close_info.get("close_attempted"):
        time.sleep(1.0)

    service_info = close_services_before_move(target)
    if service_info.get("service_stop_attempted"):
        time.sleep(1.0)

    if service_info.get("service_stop_attempted") or (
        close_info.get("close_attempted") and not close_info.get("close_success", False)
    ):
        retry_close_info = close_processes_before_move(target)
        if retry_close_info.get("close_attempted"):
            close_info = {
                **retry_close_info,
                "initial_close": close_info,
                "retry_close": retry_close_info,
                "close_attempts": list(close_info.get("close_attempts", []))
                + list(retry_close_info.get("close_attempts", [])),
            }

    if close_info.get("close_attempted") and not close_info.get("close_success", False):
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM app relocation blocked because related process could not be closed.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    **close_info,
                    **service_info,
                    "relocate_status": "preflight_failed",
                    "action_blocked_before_move": True,
                    "possible_file_locked": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="process_close_failed",
        )

    if service_info.get("service_stop_attempted") and not service_info.get("service_stop_success", False):
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM app relocation blocked because related service could not be stopped.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    **close_info,
                    **service_info,
                    "relocate_status": "preflight_failed",
                    "action_blocked_before_move": True,
                    "possible_file_locked": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="service_stop_failed",
        )

    copy_started = time.monotonic()

    try:
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(str(source_path), str(dest_path))
    except Exception as exc:
        _remove_incomplete_destination(dest_path)
        error_data = move_error_payload(exc)
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM app relocation copy failed.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    **close_info,
                    **service_info,
                    **error_data,
                    "relocate_status": "copy_failed",
                    "copy_duration_ms": round((time.monotonic() - copy_started) * 1000, 2),
                    "rollback_completed": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="copy_failed",
        )

    copy_duration_ms = round((time.monotonic() - copy_started) * 1000, 2)

    try:
        source_path.rename(backup_original_path)
    except Exception as exc:
        _remove_incomplete_destination(dest_path)
        error_data = move_error_payload(exc)
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM app relocation could not rename original directory.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    **close_info,
                    **service_info,
                    **error_data,
                    "relocate_status": "original_rename_failed",
                    "copy_duration_ms": copy_duration_ms,
                    "backup_original_created": False,
                    "rollback_completed": True,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="original_rename_failed",
        )

    junction_result = run_command(
        ["cmd", "/c", "mklink", "/J", str(source_path), str(dest_path)],
        timeout_sec=20,
    )

    try:
        junction_rc = int(junction_result.get("returncode", 1))
    except Exception:
        junction_rc = 1

    if junction_rc != 0:
        rollback = _restore_original_after_failed_junction(source_path, backup_original_path)
        if rollback.get("rollback_completed"):
            _remove_incomplete_destination(dest_path)

        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message="VM app relocation could not create compatibility junction.",
            data=_relocate_common_data(
                source_path=source_path,
                dest_path=dest_path,
                backup_original_path=backup_original_path,
                started=started,
                extra={
                    **close_info,
                    **service_info,
                    **junction_result,
                    **rollback,
                    "relocate_status": "junction_create_failed",
                    "copy_duration_ms": copy_duration_ms,
                    "backup_original_created": True,
                    "junction_created": False,
                    "junction_returncode": junction_rc,
                    "relocate_target_mode": relocate_target_mode,
                },
            ),
            error="junction_create_failed",
        )

    return receipt(
        ok=True,
        request_id=request_id,
        action=action,
        message="VM app relocation completed.",
        data=_relocate_common_data(
            source_path=source_path,
            dest_path=dest_path,
            backup_original_path=backup_original_path,
            started=started,
            extra={
                **close_info,
                **service_info,
                "relocate_status": "completed",
                "copy_duration_ms": copy_duration_ms,
                "backup_original_created": True,
                "junction_created": True,
                "verify_pending": True,
                "junction_result": junction_result,
                "junction_returncode": junction_rc,
                "relocate_target_mode": relocate_target_mode,
            },
        ),
    )


def action_app_update(payload: dict[str, Any]) -> dict[str, Any]:
    if not normalize_bool(CONFIG.get("enable_app_update", False)):
        return action_not_enabled(payload, "app.update")

    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}

    updater_path = clean_string(target.get("updater_path", ""))
    update_source_dir = clean_string(target.get("update_source_dir", ""))
    install_dir = clean_string(target.get("install_dir", ""))

    if updater_path:
        try:
            path = resolve_path(updater_path)
            if not path.exists():
                return receipt(ok=False, request_id=request_id, action="app.update", message="Updater not found.", error=f"not_found: {path}")
            result = run_command([str(path)], timeout_sec=process_timeout(options))
            return receipt(
                ok=int(result.get("returncode", 1)) == 0,
                request_id=request_id,
                action="app.update",
                message="VM updater executed.",
                data={"updater_path": str(path), **result},
                error="" if int(result.get("returncode", 1)) == 0 else str(result.get("stderr", "")),
            )
        except Exception as exc:
            return receipt(ok=False, request_id=request_id, action="app.update", message="VM updater failed.", error=str(exc))

    if update_source_dir and install_dir:
        try:
            source = resolve_path(update_source_dir)
            dest = resolve_path(install_dir)
            if not source.exists() or not source.is_dir():
                return receipt(ok=False, request_id=request_id, action="app.update", message="Update source not found.", error=f"not_found: {source}")

            backup = BACKUPS_ROOT / f"{dest.name}_{int(time.time())}"
            if dest.exists():
                shutil.copytree(str(dest), str(backup), dirs_exist_ok=True)
            shutil.copytree(str(source), str(dest), dirs_exist_ok=True)

            return receipt(
                ok=True,
                request_id=request_id,
                action="app.update",
                message="VM app update by directory copy executed.",
                data={
                    "install_dir": str(dest),
                    "update_source_dir": str(source),
                    "backup_path": str(backup),
                },
            )
        except Exception as exc:
            return receipt(ok=False, request_id=request_id, action="app.update", message="VM app update failed.", error=str(exc))

    return receipt(
        ok=False,
        request_id=request_id,
        action="app.update",
        message="Missing updater_path or update_source_dir.",
        error="missing_update_strategy",
    )


def action_browser_search_open(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}

    query = clean_string(target.get("query", ""))
    engine = clean_string(target.get("engine", "bing")).lower()
    browser_path = clean_string(target.get("browser_path", ""))

    if not query:
        return receipt(ok=False, request_id=request_id, action="browser.search_open", message="Missing query.", error="missing_query")

    base_url = {
        "bing": "https://www.bing.com/search?q=",
        "google": "https://www.google.com/search?q=",
        "baidu": "https://www.baidu.com/s?wd=",
    }.get(engine, "https://www.bing.com/search?q=")

    url = base_url + urllib.parse.quote_plus(query)

    try:
        if browser_path:
            path = resolve_path(browser_path)
            if path.exists():
                subprocess.Popen([str(path), url])
            else:
                webbrowser.open(url)
        else:
            webbrowser.open(url)

        return receipt(
            ok=True,
            request_id=request_id,
            action="browser.search_open",
            message="VM browser search opened.",
            data={"engine": engine, "query": query, "url": url, "browser_path": browser_path},
        )
    except Exception as exc:
        return receipt(
            ok=False,
            request_id=request_id,
            action="browser.search_open",
            message="VM browser search failed.",
            error=str(exc),
            data={"engine": engine, "query": query, "url": url},
        )


def action_session_status(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    return receipt(
        ok=True,
        request_id=request_id,
        action="session.status",
        message="VM session status.",
        data={
            "base_dir": str(BASE_DIR),
            "workspace_root": str(WORKSPACE_ROOT),
            "runtime_root": str(RUNTIME_ROOT),
            "temp_root": str(TEMP_ROOT),
            "downloads_root": str(DOWNLOADS_ROOT),
            "apps_root": str(APPS_ROOT),
            "moved_root": str(MOVED_ROOT),
            "updates_root": str(UPDATES_ROOT),
            "backups_root": str(BACKUPS_ROOT),
            "quarantine_root": str(QUARANTINE_ROOT),
            "developer_mode": bool(CONFIG.get("developer_mode", False)),
        },
    )


def safe_clear_dir(path: Path) -> dict[str, Any]:
    path.mkdir(parents=True, exist_ok=True)
    removed = 0
    errors: list[str] = []

    for child in path.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
            removed += 1
        except Exception as exc:
            errors.append(f"{child}: {exc}")

    return {"path": str(path), "removed": removed, "errors": errors}


def action_session_cleanup(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}

    targets = [TEMP_ROOT, RUNTIME_ROOT / "requests", RUNTIME_ROOT / "responses"]

    if normalize_bool(options.get("cleanup_workspace", False)):
        targets.append(WORKSPACE_ROOT)
    if normalize_bool(options.get("cleanup_downloads", False)):
        targets.append(DOWNLOADS_ROOT)

    results = [safe_clear_dir(p) for p in targets]

    return receipt(
        ok=True,
        request_id=request_id,
        action="session.cleanup",
        message="VM temporary session data cleaned.",
        data={"results": results},
    )


def action_raw_shell(payload: dict[str, Any]) -> dict[str, Any]:
    request_id = clean_string(payload.get("request_id")) or new_request_id()
    options = payload.get("options", {}) if isinstance(payload.get("options"), dict) else {}
    target = payload.get("target", {}) if isinstance(payload.get("target"), dict) else {}

    if not (normalize_bool(CONFIG.get("developer_mode", False)) and normalize_bool(CONFIG.get("allow_raw_shell", False))):
        return receipt(
            ok=False,
            request_id=request_id,
            action="raw.shell",
            message="raw.shell is disabled.",
            error="raw_shell_disabled",
        )

    command = clean_string(target.get("command", ""))
    if not command:
        return receipt(ok=False, request_id=request_id, action="raw.shell", message="Missing command.", error="missing_command")

    try:
        result = run_command(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            timeout_sec=process_timeout(options),
        )
        return receipt(
            ok=int(result.get("returncode", 1)) == 0,
            request_id=request_id,
            action="raw.shell",
            message="VM raw shell executed.",
            data=result,
            error="" if int(result.get("returncode", 1)) == 0 else str(result.get("stderr", "")),
        )
    except Exception as exc:
        return receipt(ok=False, request_id=request_id, action="raw.shell", message="VM raw shell failed.", error=str(exc))
