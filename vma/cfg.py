# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import os

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "agent_config.json"

PACKAGE_VERSION = "0.4.2"
PROTOCOL_VERSION = "v4.agent.1"

def _default_config() -> dict[str, Any]:
    return {
        "agent_name": "desktop_vm_agent",
        "protocol_version": PROTOCOL_VERSION,
        "package_version": PACKAGE_VERSION,

        "host": "0.0.0.0",
        "port": 8765,
        "token": "",

        "developer_mode": False,
        "allow_raw_shell": False,

        "allow_legacy_apps_api": True,
        "allow_action_api": True,
        "allow_dynamic_app_scan": True,
        "allow_any_vm_file_read": False,
        "allow_any_vm_file_write": False,

        # 高危动作默认关闭。Host 三省六部通过后，VM 端仍需显式打开这些开关才执行。
        "enable_app_uninstall": False,
        "enable_app_move": False,
        "enable_app_update": False,
        "enable_file_write_actions": False,

        "default_timeout_sec": 10,
        "scan_timeout_sec": 12,
        "max_request_body_bytes": 1048576,

        "test_root": r"C:\AI_VM_TEST",
        "workspace_root": r"C:\AI_VM_TEST\workspace",
        "runtime_root": r"C:\AI_VM_TEST\runtime",
        "temp_root": r"C:\AI_VM_TEST\temp",
        "downloads_root": r"C:\AI_VM_TEST\downloads",
        "apps_root": r"C:\AI_VM_TEST\workspace\apps",
        "moved_root": r"C:\AI_VM_TEST\workspace\apps_moved",
        "updates_root": r"C:\AI_VM_TEST\workspace\apps_update",
        "backups_root": r"C:\AI_VM_TEST\backups",
        "quarantine_root": r"C:\AI_VM_TEST\quarantine",
        "file_read_roots": [
            r"C:\AI_VM_TEST",
        ],
        "file_write_roots": [
            r"C:\AI_VM_TEST\workspace",
            r"C:\AI_VM_TEST\temp",
            r"C:\AI_VM_TEST\backups",
            r"C:\AI_VM_TEST\quarantine",
        ],

        # 这是最浅边界，不替代 Host 三省六部。
        # 只用于防止误操作系统核心目录。
        "deny_roots": [
            r"C:\Windows",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
            r"C:\System Volume Information",
        ],
    }


def load_config() -> dict[str, Any]:
    config = _default_config()

    if CONFIG_PATH.exists():
        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                config.update(loaded)
        except Exception as exc:
            print(f"[VM_AGENT] failed to load agent_config.json: {exc}", flush=True)

    env_host = os.environ.get("VM_AGENT_HOST", "").strip()
    env_port = os.environ.get("VM_AGENT_PORT", "").strip()
    env_token = os.environ.get("VM_AGENT_TOKEN", "")

    if env_host:
        config["host"] = env_host
    if env_port:
        try:
            config["port"] = int(env_port)
        except Exception:
            pass
    if env_token:
        config["token"] = env_token

    return config


CONFIG = load_config()

HOST = str(CONFIG.get("host", "0.0.0.0") or "0.0.0.0")
PORT = int(CONFIG.get("port", 8765) or 8765)
TOKEN = str(CONFIG.get("token", "") or "")

WORKSPACE_ROOT = Path(str(CONFIG.get("workspace_root", r"C:\AI_VM_TEST\workspace"))).expanduser()
TEST_ROOT = Path(str(CONFIG.get("test_root", str(WORKSPACE_ROOT.parent)))).expanduser()
RUNTIME_ROOT = Path(str(CONFIG.get("runtime_root", r"C:\AI_VM_TEST\runtime"))).expanduser()
TEMP_ROOT = Path(str(CONFIG.get("temp_root", r"C:\AI_VM_TEST\temp"))).expanduser()
DOWNLOADS_ROOT = Path(str(CONFIG.get("downloads_root", r"C:\AI_VM_TEST\downloads"))).expanduser()
APPS_ROOT = Path(str(CONFIG.get("apps_root", r"C:\AI_VM_TEST\workspace\apps"))).expanduser()
MOVED_ROOT = Path(str(CONFIG.get("moved_root", r"C:\AI_VM_TEST\workspace\apps_moved"))).expanduser()
UPDATES_ROOT = Path(str(CONFIG.get("updates_root", r"C:\AI_VM_TEST\workspace\apps_update"))).expanduser()
BACKUPS_ROOT = Path(str(CONFIG.get("backups_root", r"C:\AI_VM_TEST\backups"))).expanduser()
QUARANTINE_ROOT = Path(str(CONFIG.get("quarantine_root", r"C:\AI_VM_TEST\quarantine"))).expanduser()

DEFAULT_TIMEOUT_SEC = int(CONFIG.get("default_timeout_sec", 10) or 10)
SCAN_TIMEOUT_SEC = int(CONFIG.get("scan_timeout_sec", 12) or 12)
MAX_BODY_BYTES = int(CONFIG.get("max_request_body_bytes", 1048576) or 1048576)
