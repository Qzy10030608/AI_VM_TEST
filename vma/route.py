# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any

from .apps import (
    action_app_scan, action_app_locate, action_app_launch, action_app_close,
    action_app_uninstall, action_app_move, action_app_relocate, action_app_update,
    action_browser_search_open, action_session_status, action_session_cleanup,
    action_raw_shell,
)
from .files import (
    action_file_list, action_file_inspect, action_file_locate, action_file_open,
    action_file_copy, action_file_move, action_file_rename, action_file_delete,
    action_file_restore, action_file_mkdir, action_file_touch, action_file_create,
    action_file_close, action_file_close_all,
)
from .util import clean_string, new_request_id, receipt

ACTION_HANDLERS = {
    "app.scan": action_app_scan,
    "app.locate": action_app_locate,
    "app.launch": action_app_launch,
    "app.close": action_app_close,
    "app.uninstall": action_app_uninstall,
    "app.move": action_app_move,
    "app.relocate": action_app_relocate,
    "app.update": action_app_update,

    "file.list": action_file_list,
    "file.inspect": action_file_inspect,
    "file.locate": action_file_locate,
    "file.open": action_file_open,
    "file.close": action_file_close,
    "file.close.all": action_file_close_all,
    "file.copy": action_file_copy,
    "file.move": action_file_move,
    "file.rename": action_file_rename,
    "file.delete": action_file_delete,
    "file.restore": action_file_restore,
    "file.mkdir": action_file_mkdir,
    "file.touch": action_file_touch,
    "file.create": action_file_create,

    # 语义别名：Host 可以统一用 file.*，也可以传 folder.*。
    "folder.open": action_file_open,
    "folder.close": action_file_close,
    "folder.close.all": action_file_close_all,
    "folder.locate": action_file_locate,
    "folder.rename": action_file_rename,
    "folder.move": action_file_move,
    "folder.delete": action_file_delete,
    "folder.restore": action_file_restore,
    "folder.mkdir": action_file_mkdir,
    "folder.create": action_file_create,

    "browser.search_open": action_browser_search_open,
    "session.status": action_session_status,
    "session.cleanup": action_session_cleanup,
    "raw.shell": action_raw_shell,
}


def dispatch_action(payload: dict[str, Any]) -> dict[str, Any]:
    action = clean_string(payload.get("action", "")).lower()
    request_id = clean_string(payload.get("request_id")) or new_request_id()

    if not action:
        return receipt(ok=False, request_id=request_id, action="", message="Missing action.", error="missing_action")

    handler = ACTION_HANDLERS.get(action)
    if handler is None:
        return receipt(
            ok=False,
            request_id=request_id,
            action=action,
            message=f"Unsupported action: {action}",
            error="unsupported_action",
        )

    return handler(payload)
