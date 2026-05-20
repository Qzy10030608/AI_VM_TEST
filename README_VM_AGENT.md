# VM Agent 虚拟机连接说明

本文件是 **小助理 Demo / Desktop AI Assistant** 的 VM Agent 专用 README，用于说明虚拟机连接方式、VM Agent 的职责边界、Host 小助手如何通过三省六部治理链连接虚拟机，以及文件区、软件区动作在 VM 中的执行规则。

> 本文不是主项目 README，也不是最终用户安装包说明。它面向开发、测试和 GitHub 工程说明，用于放在 VM Agent 目录或 `docs/` 目录中。

---

## 1. VM Agent 是什么

VM Agent 是运行在虚拟机内部的轻量执行器，负责接收 Host 小助手发来的结构化请求，并只在虚拟机内部执行文件、软件、浏览器和会话类动作。

它的核心定位是：

- **薄连接器**：提供 HTTP 接口，让 Host 小助手可以连接 VM。
- **薄执行器**：只执行已经结构化的 action，不理解自然语言。
- **信号收发器**：返回标准 receipt，供 Host 侧 UI、御史台报告和少府材料记录。
- **VM 内边界守卫**：通过 `agent_config.json`、`deny_roots`、`file_read_roots`、`file_write_roots` 和危险动作开关防止误操作系统核心目录。

VM Agent 不负责完整权限决策。权限审议、风险判断、任务调度、checkpoint、报告和用户回执仍由 Host 小助手中的秦治理链完成。

---

## 2. 总体连接关系

VM Agent 与小助手主项目之间的关系如下：

```text
用户文字 / 用户语音 / 控制中心按钮
        ↓
Host 小助手主程序
        ↓
LanguageInteractionCenter / Tianting Bridge
        ↓
生成结构化 DesktopTask
        ↓
QinRuntimeService
        ↓
三省六部治理链
        ↓
工部 VM Adapter
        ↓
HTTP 请求 VM Agent
        ↓
VM 内文件区 / 软件区执行
        ↓
标准 receipt 回传 Host
        ↓
礼部回执 / 少府材料 / 御史台报告 / UI 状态展示
```

重要原则：

1. LLM 不直接调用 VM Agent。
2. UI 不直接越过秦治理链执行 VM 动作。
3. VM Agent 不理解自然语言，只接收结构化 action。
4. VM 失败不能自动回落到 Host。
5. VM Agent 返回的所有结果必须标记 `executed_in="vm"`。

---

## 3. VM Agent 推荐目录结构

推荐将 VM Agent 放在虚拟机中的独立目录，例如：

```text
C:\AI_VM_TEST\agent\
├─ desktop_vm_agent.py          # HTTP 入口、GET/POST 路由、服务启动
├─ agent_config.json            # VM Agent 配置文件
├─ start_agent.bat              # 可选：一键启动脚本
├─ README_VM_AGENT.md           # 本说明文件
└─ vma/
   ├─ __init__.py
   ├─ cfg.py                    # 配置、路径、版本、端口、开关
   ├─ util.py                   # receipt、路径校验、命令执行、通用工具
   ├─ files.py                  # 文件区动作：roots/list/open/close/rename/move/delete/restore/create
   ├─ apps.py                   # 软件区动作：扫描、启动、定位、关闭、卸载、移动、更新
   └─ route.py                  # action 分发表与 dispatch_action
```

模块职责：

| 文件 | 职责 | 修改建议 |
|---|---|---|
| `desktop_vm_agent.py` | HTTP 接收、接口路由、启动服务、兼容旧接口 | 保持轻量，不堆业务逻辑 |
| `vma/cfg.py` | 读取 `agent_config.json`，暴露端口、路径、开关和版本 | 新配置项集中放这里 |
| `vma/util.py` | 公共工具、receipt、路径边界、命令执行 | 不放具体业务动作 |
| `vma/files.py` | 文件区浏览、打开、关闭、复制、移动、删除、恢复、创建 | 文件动作主要修改点 |
| `vma/apps.py` | 软件扫描、启动、定位、关闭、卸载、迁移、更新 | 高风险软件动作必须保留开关 |
| `vma/route.py` | action → handler 分发 | 新 action 只补分发表 |

---

## 4. 三省六部在 VM 连接中的作用

VM Agent 只是执行出口之一。真正的治理链仍在 Host 小助手中完成。

### 4.1 三省职责

| 机构 | VM 连接中的职责 | 不允许做的事 |
|---|---|---|
| 中书省 | 将用户语音、文字或 UI 操作整理成标准 `DesktopTask` | 不直接调用 VM Agent |
| 门下省 | 审议模式、权限、动作风险、对象来源、是否允许进入 VM 测试 | 不把 VM 测试权限混入 Host 权限 |
| 尚书省 | 根据当前模式与出口选择 `sandbox / vm / host` 路由 | 不允许 VM 失败后回落 Host |

### 4.2 六部职责

| 部门 | VM 连接中的职责 |
|---|---|
| 吏部 | 维护 VM 文件对象、VM 软件对象、候选目标和对象归类 |
| 户部 | 记录调用次数、耗时、失败率、扫描统计和执行账本 |
| 礼部 | 生成用户可读回执、权限提示、拒绝原因和 UI 文案 |
| 兵部 | 负责节流、超时、急停、防重复点击和连续失败熔断 |
| 刑部 | 审查删除、卸载、移动、更新等高风险动作，必要时要求确认 |
| 工部 | 调用 VM Adapter，将已审议任务发送到 VM Agent |

### 4.3 扩展机构

| 机构 | VM 连接中的职责 |
|---|---|
| 少府 | 保存 checkpoint、隔离删除、恢复 token、manifest 和回退材料 |
| 御史台 | 记录 VM 执行事件、request_id、receipt、测试矩阵和报告 |
| 黑冰台 | 负责目标解析，尤其是关闭文件、关闭文件夹、关闭软件时的目标匹配 |
| 天庭 | 负责连接桥接、命令候选、VM 连接 worker，不做最终权限判定 |
| 星君 | 负责 VM 测试计划、测试矩阵和 dry-run / runner 验证 |

---

## 5. VM 执行出口与 Host / Sandbox 的区别

| 出口 | 显示对象 | 是否真实执行 | 执行位置 | 用途 |
|---|---|---|---|---|
| Sandbox | Host 文件 / Host 软件治理数据 | 否 | 不触达真实系统 | 审议、权限、回执模拟 |
| VM | VM 文件 / VM 软件清单 | 是 | 虚拟机内部 | V3 / V4 文件区和软件区真实测试 |
| Host | Host 文件 / Host 软件治理数据 | 是 | 宿主机 | trusted 模式下灰度真实执行 |

VM 的关键边界：

- VM 只执行虚拟机内部路径。
- VM Agent 不写 Host 权限配置。
- VM 软件列表来自 `/apps/list`，不读取 Host 的软件缓存。
- VM 文件列表来自 `/files/roots` 和 `/files/list`，不直接读取 Host 文件区。
- VM 失败不得自动转为 Host 执行。

---

## 6. 启动 VM Agent

在虚拟机中进入 VM Agent 所在目录：

```powershell
cd C:\AI_VM_TEST\agent
python desktop_vm_agent.py
```

启动后控制台应显示类似信息：

```text
desktop_vm_agent
package_version : 0.4.2
protocol_version: v4.agent.1
listen          : http://0.0.0.0:8765
GET  /health
GET  /capabilities
GET  /apps/list
GET  /files/roots
GET  /files/list
POST /action
```

如果需要使用管理员权限测试软件移动、更新、卸载等高风险动作，应以管理员身份启动 PowerShell 或命令行，再运行 VM Agent。

---

## 7. Host 侧连接检查

在 Host 小助手所在机器上，先确认虚拟机 IP，例如：

```text
192.168.114.128
```

然后测试健康检查：

```powershell
Invoke-RestMethod http://192.168.114.128:8765/health | ConvertTo-Json -Depth 10
```

测试能力声明：

```powershell
Invoke-RestMethod http://192.168.114.128:8765/capabilities | ConvertTo-Json -Depth 10
```

如果这两个接口可以返回 JSON，说明 Host 可以连接 VM Agent。

---

## 8. VM Agent HTTP 接口

| 接口 | 方法 | 用途 | 说明 |
|---|---|---|---|
| `/health` | GET | 健康检查 | 返回版本、主机名、PID、feature flags |
| `/capabilities` | GET | 能力声明 | 返回 action 列表、危险动作开关、读写根目录 |
| `/apps/list` | GET | 软件列表 | 旧兼容接口，用于 VM 软件区展示 |
| `/files/roots` | GET | 文件根目录 | 返回 VM 内部磁盘根目录和测试根目录 |
| `/files/list` | GET | 文件列表 | 按 `root_id + relative_path` 列出一层目录 |
| `/action` | POST | 主执行接口 | V4 推荐入口，所有文件/软件动作统一走 action |

`/action` 示例：

```json
{
  "request_id": "vm-test-001",
  "protocol_version": "v4.agent.1",
  "action": "file.inspect",
  "target": {
    "path": "C:\\AI_VM_TEST\\workspace\\demo.txt",
    "target_type": "file"
  },
  "options": {
    "timeout_sec": 10
  }
}
```

---

## 9. agent_config.json 配置示例

`agent_config.json` 用于配置 VM Agent 的端口、路径、安全边界和高风险动作开关。

推荐基础配置：

```json
{
  "agent_name": "desktop_vm_agent",
  "host": "0.0.0.0",
  "port": 8765,
  "token": "",

  "allow_legacy_apps_api": true,
  "allow_action_api": true,
  "allow_dynamic_app_scan": true,

  "allow_any_vm_file_read": false,
  "allow_any_vm_file_write": false,

  "enable_file_write_actions": false,
  "enable_app_uninstall": false,
  "enable_app_move": false,
  "enable_app_update": false,

  "test_root": "C:\\AI_VM_TEST",
  "workspace_root": "C:\\AI_VM_TEST\\workspace",
  "runtime_root": "C:\\AI_VM_TEST\\runtime",
  "temp_root": "C:\\AI_VM_TEST\\temp",
  "downloads_root": "C:\\AI_VM_TEST\\downloads",
  "apps_root": "C:\\AI_VM_TEST\\workspace\\apps",
  "moved_root": "C:\\AI_VM_TEST\\workspace\\apps_moved",
  "updates_root": "C:\\AI_VM_TEST\\workspace\\apps_update",
  "backups_root": "C:\\AI_VM_TEST\\backups",
  "quarantine_root": "C:\\AI_VM_TEST\\quarantine",

  "file_read_roots": [
    "C:\\AI_VM_TEST"
  ],
  "file_write_roots": [
    "C:\\AI_VM_TEST\\workspace",
    "C:\\AI_VM_TEST\\temp",
    "C:\\AI_VM_TEST\\backups",
    "C:\\AI_VM_TEST\\quarantine"
  ],
  "deny_roots": [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\System Volume Information"
  ]
}
```

测试阶段如需放开 VM 内读写，可临时调整：

```json
{
  "enable_file_write_actions": true,
  "allow_any_vm_file_read": true,
  "allow_any_vm_file_write": true
}
```

注意：即使 VM 端放开读写，也只表示虚拟机内部测试放开，不代表 Host 可以真实执行。

---

## 10. 文件区动作

文件区主要由 `vma/files.py` 实现。

| Action | 类型 | 说明 |
|---|---|---|
| `file.list` | read | 列出目录一层对象 |
| `file.inspect` | read | 查看文件或文件夹元信息 |
| `file.locate` / `folder.locate` | read | 在 VM Explorer 中定位对象 |
| `file.open` / `folder.open` | read/runtime | 打开文件或文件夹；已打开则激活 |
| `file.close` / `folder.close` | runtime/high | 按路径关闭文件或文件夹窗口 |
| `file.close.all` / `folder.close.all` | runtime/high | 关闭同路径所有匹配窗口 |
| `file.rename` / `folder.rename` | write | 重命名对象 |
| `file.move` / `folder.move` | write | 移动对象，并生成少府临时材料 |
| `file.copy` | write | 复制文件或文件夹 |
| `file.delete` / `folder.delete` | high/write | 隔离删除，生成 `restore_token` 和 manifest |
| `file.restore` / `folder.restore` | high/write | 根据 token 或 manifest 恢复 |
| `file.mkdir` / `folder.mkdir` | write | 创建文件夹 |
| `file.touch` / `file.create` | write | 创建文件 |

文件区固定规则：

- `list` 只列出一层，不递归全盘。
- `open` 和 `close` 语义分离，关闭不依赖之前打开的 ID。
- `folder.close` 必须按 Explorer 当前路径关闭，不能强杀全局 `explorer.exe`。
- `file.delete` 第一版不真删除，统一移动到少府隔离区。
- `restore` 必须基于 `restore_token` 或 manifest，不允许凭空推断。
- 写动作必须经过 `enable_file_write_actions`、`file_write_roots` 和 `deny_roots` 检查。

---

## 11. 软件区动作

软件区主要由 `vma/apps.py` 实现。

| Action | 风险 | 说明 |
|---|---|---|
| `app.scan` | low | 动态扫描 VM 软件列表 |
| `app.locate` | low | 定位软件入口或安装目录 |
| `app.launch` | medium | 启动 VM 内软件 |
| `app.close` | medium/high | 按白名单进程名关闭软件 |
| `app.uninstall` | critical | 启动卸载程序，默认关闭 |
| `app.move` / `app.relocate` | critical | 迁移软件目录，默认关闭 |
| `app.update` | critical | 执行更新器或目录覆盖，默认关闭 |

软件扫描来源：

- 注册表 Uninstall 信息
- 开始菜单 / 桌面快捷方式
- 内置 fallback 软件，例如记事本、Edge、Chrome、计算器、画图
- 合并主程序与卸载器
- 过滤系统噪声工具，例如 PowerShell、任务管理器、注册表编辑器等

软件区固定规则：

- VM 软件对象权限显示为 `test` / `测试`。
- VM 软件区不写 Host 权限文件。
- `app.close` 应按 `process_name` 或 `process_names` 关闭，不做模糊系统进程关闭。
- 卸载、移动、更新必须由 Host 三省六部确认，并且 VM 端开关也要显式打开。

---

## 12. 标准回执 receipt

所有 VM Agent 动作都必须返回结构化 receipt。

示例：

```json
{
  "ok": true,
  "request_id": "vm-xxx",
  "protocol_version": "v4.agent.1",
  "agent": "desktop_vm_agent",
  "package_version": "0.4.2",
  "executed_in": "vm",
  "action": "file.open",
  "hostname": "VM-WINDOWS",
  "system": "Windows-10-...",
  "pid": 1234,
  "timestamp_ms": 1710000000000,
  "message": "VM file open executed.",
  "status": "ok",
  "data": {},
  "error": ""
}
```

要求：

- 成功时 `ok=true`。
- 失败时 `ok=false`，并填写 `error`。
- 必须包含 `executed_in="vm"`。
- 文件动作应返回 `path`、`target_path`、`target_type`。
- 打开动作应返回 `open_handle`、`pid/pids`、`tracked`。
- 删除动作应返回 `restore_token`、`quarantine_path`、`manifest_path`。
- 移动/重命名动作应返回 `source_path`、`dest_path`、`old_path`、`new_path`。

---

## 13. Host 侧测试命令

Host 主项目中可以使用测试 runner 调用 VM Agent。示例：

```powershell
python tools\vm_file_action_test_runner.py inspect --target-path "C:\AI_VM_TEST\workspace\测试\4321.txt" --target-type file
```

打开文件：

```powershell
python tools\vm_file_action_test_runner.py open --target-path "C:\AI_VM_TEST\workspace\测试\4321.txt" --target-type file
```

关闭文件：

```powershell
python tools\vm_file_action_test_runner.py close --target-path "C:\AI_VM_TEST\workspace\测试\4321.txt" --target-type file
```

打开文件夹：

```powershell
python tools\vm_file_action_test_runner.py open --target-path "C:\AI_VM_TEST\workspace\测试" --target-type directory
```

关闭文件夹：

```powershell
python tools\vm_file_action_test_runner.py close --target-path "C:\AI_VM_TEST\workspace\测试" --target-type directory
```

关闭同路径所有窗口：

```powershell
python tools\vm_file_action_test_runner.py close --target-path "C:\AI_VM_TEST\workspace\测试" --target-type directory --close-mode all
```

---

## 14. GitHub 上传建议

可以上传：

```text
desktop_vm_agent.py
vma/__init__.py
vma/cfg.py
vma/util.py
vma/files.py
vma/apps.py
vma/route.py
README_VM_AGENT.md
agent_config.example.json
start_agent.example.bat
```

不建议上传：

```text
agent_config.json
C:\AI_VM_TEST\runtime\
C:\AI_VM_TEST\temp\
C:\AI_VM_TEST\backups\
C:\AI_VM_TEST\quarantine\
C:\AI_VM_TEST\workspace\ 私人测试文件
运行日志
真实 token
虚拟机专用本地路径配置
```

如果需要提供配置文件，请上传 `agent_config.example.json`，不要上传真实 `agent_config.json`。

---

## 15. 最终原则

VM Agent 不是新的权限中心，而是小助手三省六部治理链下的 VM 执行出口。

最终规则：

```text
Host 小助手负责理解、审议、调度、记录和回执。
VM Agent 负责在虚拟机内执行结构化动作。
Sandbox 负责模拟回执。
Host 真实执行必须单独灰度开放。
三者不能互相自动回落。
```

因此，VM Agent 的设计目标不是“让 AI 随便控制虚拟机”，而是让小助手在可审计、可回退、可测试的边界内完成桌面动作验证。
