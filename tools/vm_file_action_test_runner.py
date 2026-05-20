# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from services.desktop.qin.gongbu.vm_test.vm_action_service import VmActionService  # noqa: E402


def build_task(
    *,
    action: str,
    target_path: str,
    target_type: str,
    close_mode: str = "one",
) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "path": target_path,
        "target_path": target_path,
        "target_type": target_type,
    }

    if action in {"file.close", "file.close.all", "folder.close", "folder.close.all"}:
        arguments["close_mode"] = "all" if close_mode == "all" else "one"

    return {
        "request_id": uuid4().hex,
        "action": action,
        "target_id": target_path,
        "target_name": target_path,
        "arguments": arguments,
        "meta": {
            "source": "host_vm_file_action_test_runner",
            "test_backend": "vm",
            "host_execution_enabled": False,
        },
    }


def build_review_decision() -> dict[str, Any]:
    return {
        "review_stage": "host_vm_file_action_test",
        "decision": "allow_vm_test",
        "risk_level": "low_to_medium",
        "route_result": "vm_only",
        "checkpoint_id": "",
        "material_id": "",
        "material_status": "",
    }


def normalize_action(command: str, target_type: str, close_mode: str) -> str:
    command = str(command or "").strip().lower()
    target_type = str(target_type or "").strip().lower()
    close_mode = "all" if str(close_mode or "").strip().lower() == "all" else "one"

    is_folder = target_type in {"directory", "folder", "dir"}

    if command == "open":
        return "folder.open" if is_folder else "file.open"

    if command == "close":
        if is_folder:
            return "folder.close.all" if close_mode == "all" else "folder.close"
        return "file.close.all" if close_mode == "all" else "file.close"

    if command == "locate":
        return "folder.locate" if is_folder else "file.locate"

    if command == "inspect":
        return "file.inspect"

    raise ValueError(f"unsupported command: {command}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Host-side VM file/folder action test runner. 宿主机发起，VM Agent 执行。"
    )
    parser.add_argument(
        "command",
        choices=["open", "close", "locate", "inspect"],
        help="测试动作：open=打开或置顶，close=按路径关闭，locate=定位，inspect=检查",
    )
    parser.add_argument(
        "--target-path",
        required=True,
        help="VM 内目标路径，例如 C:\\AI_VM_TEST\\workspace\\测试\\4321.txt",
    )
    parser.add_argument(
        "--target-type",
        default="file",
        choices=["file", "directory", "folder", "dir"],
        help="目标类型：file 或 directory",
    )
    parser.add_argument(
        "--close-mode",
        default="one",
        choices=["one", "all"],
        help="关闭模式：one=关闭一个匹配窗口，all=关闭所有同路径窗口",
    )

    args = parser.parse_args()

    try:
        action = normalize_action(args.command, args.target_type, args.close_mode)
        target_type = "directory" if args.target_type in {"directory", "folder", "dir"} else "file"

        task = build_task(
            action=action,
            target_path=args.target_path,
            target_type=target_type,
            close_mode=args.close_mode,
        )
        review_decision = build_review_decision()

        service = VmActionService()
        result = service.execute_desktop_task(task, review_decision)

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if bool(result.get("ok", False)) else 1

    except Exception as exc:
        print(json.dumps({
            "ok": False,
            "error": str(exc),
            "message": "Host-side VM file action test runner failed.",
        }, ensure_ascii=False, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
