# -*- coding: utf-8 -*-
"""
desktop_vm_agent.py
V4 thin VM connector / executor

拆分版：
- desktop_vm_agent.py 只保留 HTTP 接收、路由、启动
- vma/files.py 负责文件管理区
- vma/apps.py 负责软件管理区
- vma/cfg.py 和 vma/util.py 负责配置与公共工具
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import json
import os
import platform
import urllib.parse

from vma.cfg import (
    CONFIG, HOST, PORT, TOKEN, WORKSPACE_ROOT, TEST_ROOT, RUNTIME_ROOT,
    MAX_BODY_BYTES, PACKAGE_VERSION, PROTOCOL_VERSION,
)
from vma.util import (
    ensure_dirs, receipt, json_response, clean_string, normalize_bool,
    is_running_as_admin, build_hash, vm_agent_feature_flags, new_request_id,
    resolve_path,
)
from vma.apps import scan_apps, find_app_by_id
from vma.files import (
    vm_file_roots, default_vm_file_root_id, vm_file_root_by_id,
    build_file_list_result,
)
from vma.route import ACTION_HANDLERS, dispatch_action


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        print("[VM_AGENT]", self.address_string(), fmt % args, flush=True)

    def _authorized(self) -> bool:
        if not TOKEN:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {TOKEN}"

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            raise ValueError(f"Request body too large: {length} > {MAX_BODY_BYTES}")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}

    def do_OPTIONS(self) -> None:
        json_response(self, {"ok": True})

    def do_GET(self) -> None:
        if not self._authorized():
            json_response(self, {"ok": False, "error": "unauthorized"}, status=401)
            return

        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/health":
            ensure_dirs()
            json_response(self, receipt(
                ok=True,
                action="health",
                message="VM Agent is healthy.",
                data={
                    "agent": "desktop_vm_agent",
                    "version": PACKAGE_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "mode": "thin_vm_executor",
                    "workspace": str(WORKSPACE_ROOT),
                    "runtime_root": str(RUNTIME_ROOT),
                    "hostname": platform.node(),
                    "system": platform.platform(),
                    "pid": os.getpid(),
                    "is_admin": is_running_as_admin(),
                    "build_hash": build_hash(),
                    "feature_flags": vm_agent_feature_flags(),
                },
            ))
            return

        if parsed.path == "/capabilities":
            json_response(self, receipt(
                ok=True,
                action="capabilities",
                message="VM Agent capabilities.",
                data={
                    "agent": "desktop_vm_agent",
                    "version": PACKAGE_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "build_hash": build_hash(),
                    "is_admin": is_running_as_admin(),
                    "developer_mode": bool(CONFIG.get("developer_mode", False)),
                    "legacy_apps_api": bool(CONFIG.get("allow_legacy_apps_api", True)),
                    "action_api": bool(CONFIG.get("allow_action_api", True)),
                    "dynamic_app_scan": bool(CONFIG.get("allow_dynamic_app_scan", True)),
                    "dangerous_switches": {
                        "enable_app_uninstall": bool(CONFIG.get("enable_app_uninstall", False)),
                        "enable_app_move": bool(CONFIG.get("enable_app_move", False)),
                        "enable_app_update": bool(CONFIG.get("enable_app_update", False)),
                        "enable_file_write_actions": bool(CONFIG.get("enable_file_write_actions", False)),
                        "allow_any_vm_file_read": bool(CONFIG.get("allow_any_vm_file_read", False)),
                        "allow_any_vm_file_write": bool(CONFIG.get("allow_any_vm_file_write", False)),
                        "file_read_roots": CONFIG.get("file_read_roots", []),
                        "file_write_roots": CONFIG.get("file_write_roots", []),
                    },
                    "capabilities": {
                        "legacy": {
                            "apps": ["list", "locate", "launch", "close"],
                            "files": ["roots", "list"],
                        },
                        "action": sorted(ACTION_HANDLERS.keys()),
                        "feature_flags": vm_agent_feature_flags(),
                    },
                },
            ))
            return

        if parsed.path == "/apps/list":
            if not normalize_bool(CONFIG.get("allow_legacy_apps_api", True)):
                json_response(self, {"ok": False, "error": "legacy_api_disabled"}, status=403)
                return

            from vma.util import now_ms
            started = now_ms()
            apps = scan_apps()
            json_response(self, {
                "ok": True,
                "apps": apps,
                "count": len(apps),
                "duration_ms": now_ms() - started,
                "hostname": platform.node(),
                "protocol_version": PROTOCOL_VERSION,
                "package_version": PACKAGE_VERSION,
                "scan_mode": "dynamic_plus_fallback",
            })
            return

        if parsed.path == "/files/roots":
            if not normalize_bool(CONFIG.get("allow_legacy_apps_api", True)):
                json_response(self, {"ok": False, "error": "legacy_api_disabled"}, status=403)
                return

            json_response(self, {
                "ok": True,
                "adapter_id": "vm",
                "executed_in": "vm",
                "action": "files.roots",
                "hostname": platform.node(),
                "roots": vm_file_roots(),
            })
            return

        if parsed.path == "/files/list":
            if not normalize_bool(CONFIG.get("allow_legacy_apps_api", True)):
                json_response(self, {"ok": False, "error": "legacy_api_disabled"}, status=403)
                return

            try:
                query = urllib.parse.parse_qs(parsed.query)
                root_id = query.get("root_id", [default_vm_file_root_id()])[0] or default_vm_file_root_id()
                relative_path = query.get("relative_path", [""])[0]
                raw_path = query.get("path", [""])[0]
                if raw_path and "root_id" not in query and "relative_path" not in query:
                    root_id = default_vm_file_root_id()
                    try:
                        root = vm_file_root_by_id(root_id)
                        root_path = Path(str((root or {}).get("path", TEST_ROOT))).resolve(strict=False)
                        target_path = resolve_path(raw_path, base=root_path)
                        relative_path = "" if target_path == root_path else str(target_path.relative_to(root_path))
                    except Exception:
                        relative_path = raw_path

                json_response(self, build_file_list_result(root_id=root_id, relative_path=relative_path))
            except Exception as exc:
                json_response(self, {"ok": False, "error": str(exc), "hostname": platform.node()}, status=400)
            return

        json_response(self, {
            "ok": False,
            "error": "not_found",
            "path": parsed.path,
            "hostname": platform.node(),
        }, status=404)

    def do_POST(self) -> None:
        if not self._authorized():
            json_response(self, {"ok": False, "error": "unauthorized"}, status=401)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
        except Exception as exc:
            json_response(self, {"ok": False, "error": f"Invalid JSON: {exc}", "hostname": platform.node()}, status=400)
            return

        if path == "/action":
            if not normalize_bool(CONFIG.get("allow_action_api", True)):
                json_response(self, receipt(
                    ok=False,
                    action=clean_string(body.get("action", "")),
                    request_id=clean_string(body.get("request_id", "")),
                    message="Action API is disabled.",
                    error="action_api_disabled",
                ), status=403)
                return

            result = dispatch_action(body)
            json_response(self, result, status=200 if result.get("ok") else 400)
            return

        if path in {"/apps/locate", "/apps/launch", "/apps/close"}:
            if not normalize_bool(CONFIG.get("allow_legacy_apps_api", True)):
                json_response(self, {"ok": False, "error": "legacy_api_disabled"}, status=403)
                return

            app_id = clean_string(body.get("app_id", ""))
            app = find_app_by_id(app_id)

            if app is None:
                json_response(self, {
                    "ok": False,
                    "action": path.rsplit("/", 1)[-1],
                    "app_id": app_id,
                    "error": "App not found in current VM dynamic app scan.",
                    "hostname": platform.node(),
                }, status=404)
                return

            action_name = path.rsplit("/", 1)[-1]
            target = {
                "kind": app.get("kind", "local_exe"),
                "path": app.get("path", ""),
                "target_path": app.get("target_path", ""),
                "shell_entry": app.get("shell_entry", ""),
                "locate_entry": app.get("locate_entry", ""),
                "process_name": app.get("process_name", ""),
                "process_names": app.get("process_names", []),
                "uninstall_string": app.get("uninstall_string", ""),
                "quiet_uninstall_string": app.get("quiet_uninstall_string", ""),
                "install_dir": app.get("install_dir", ""),
                "updater_path": app.get("updater_path", ""),
                "update_source_dir": app.get("update_source_dir", ""),
            }

            payload = {
                "request_id": body.get("request_id", new_request_id()),
                "protocol_version": PROTOCOL_VERSION,
                "action": f"app.{action_name}",
                "target": target,
                "options": body.get("options", {}),
                "meta": {
                    "legacy_endpoint": path,
                    "app_id": app_id,
                },
            }

            result = dispatch_action(payload)
            result["app_id"] = app_id
            if isinstance(result.get("data"), dict):
                result["data"]["app_id"] = app_id

            json_response(self, result, status=200 if result.get("ok") else 400)
            return

        json_response(self, {
            "ok": False,
            "error": "not_found",
            "path": path,
            "hostname": platform.node(),
        }, status=404)


def main() -> None:
    ensure_dirs()

    server = ThreadingHTTPServer((HOST, PORT), AgentHandler)

    print("=" * 72, flush=True)
    print("desktop_vm_agent", flush=True)
    print(f"package_version : {PACKAGE_VERSION}", flush=True)
    print(f"protocol_version: {PROTOCOL_VERSION}", flush=True)
    print(f"listen          : http://{HOST}:{PORT}", flush=True)
    print(f"base_dir        : {Path(__file__).resolve().parent}", flush=True)
    print(f"workspace       : {WORKSPACE_ROOT}", flush=True)
    print(f"runtime_root    : {RUNTIME_ROOT}", flush=True)
    print(f"dynamic_scan    : {CONFIG.get('allow_dynamic_app_scan', True)}", flush=True)
    print(f"legacy_apps_api : {CONFIG.get('allow_legacy_apps_api', True)}", flush=True)
    print(f"action_api      : {CONFIG.get('allow_action_api', True)}", flush=True)
    print("-" * 72, flush=True)
    print("GET  /health", flush=True)
    print("GET  /capabilities", flush=True)
    print("GET  /apps/list", flush=True)
    print("GET  /files/roots", flush=True)
    print("GET  /files/list", flush=True)
    print("POST /apps/locate", flush=True)
    print("POST /apps/launch", flush=True)
    print("POST /apps/close", flush=True)
    print("POST /action", flush=True)
    print("=" * 72, flush=True)

    server.serve_forever()


if __name__ == "__main__":
    main()
