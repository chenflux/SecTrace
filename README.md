# SecTrace

Windows 应急取证辅助工具 (Go + WebView2, 单文件 GUI, 无外部依赖)。

## 功能

### GUI (双击运行, 默认启动)

| 视图 | 数据源 |
|---|---|
| **浏览器历史** | Chrome / Edge / Firefox / Brave (多 Profile), SQLite 离线解析 |
| **系统活动** | 15 类痕迹合并时间线 (见下) |
| **USB 设备** | USBSTOR 注册表 (VID/PID/序列号/名称/最近插入时间) |
| **自启动项** | Run/RunOnce(8 处)、Winlogon 劫持点、AppInit_DLLs、IFEO、Active Setup、BootExecute、服务/驱动、启动文件夹, 附可疑启发式标记 |
| **已安装程序** | 3 个 Uninstall 注册表位置, 远控工具黑名单标记 (TeamViewer/AnyDesk/向日葵/RustDesk 等 24 关键词) |

### 系统活动 (15 类痕迹源)

- **程序执行历史**: Prefetch / BAM / UserAssist (ROT13 解码)
- **文件访问历史**: LNK 快捷方式 (PowerShell COM 解析) / Jump Lists / 最近文档 / 回收站 ($I 二进制解析)
- **键入历史**: RunMRU / TypedPaths / TypedURLs
- **系统事件**: 开关机 (Watchdog + GetTickCount64) / 网络连接 (NetworkList 注册表) / 登录 (ProfileList + LogonUI) / 计划任务 (Tasks XML)
- **故障事件**: BSOD Minidump
- **事件日志按需加载** (需管理员, 24h 窗口, 关键 EID 白名单): 开关机 / 网络接入断开 / 登录登出(含 RDP) / 计划任务执行, 参考 SentinelX 噪声过滤思路

### 取证时间可信度

- 精确时间戳: 直接显示
- 近似时间 (注册表键 LastWriteTime): `≈` 前缀标记
- 无时间: 显示 `-` (排序沉底), **绝不**用"当前时间"冒充事件时间

### 表格交互

列宽拖动 (双击自适应, localStorage 持久化) / 表头排序 / 实时关键字过滤 / 拖选复制 / 双击行复制 / CSV / JSON 导出

## 使用

```
SecTrace.exe                    # GUI (默认)
SecTrace.exe browse -n 50       # CLI: 浏览器历史
SecTrace.exe activity           # CLI: 系统活动
SecTrace.exe eventlog rdp       # CLI: 事件日志场景 (power/network/rdp/task)
SecTrace.exe autoruns           # CLI: 自启动项
SecTrace.exe programs           # CLI: 已安装程序
```

> 事件日志相关功能需要管理员权限 (右键 → 以管理员身份运行)。
> 需要 WebView2 Runtime (Windows 10 1803+ 一般自带)。

## 编译

```bat
build.bat
```

自动生成 4 个架构到 `outputs/`:

| 文件 | 架构 |
|---|---|
| SecTrace_windows_x86.exe | 386 (32 位) |
| SecTrace_windows_x64.exe | amd64 (64 位) |
| SecTrace_windows_arm64.exe | ARM64 (Surface / ARM PC) |

> Go 官方不支持 windows/arm 32 位, 故无此目标。

图标资源 (`rsrc_*_windows_*.syso`) 由脚本调用 [akavel/rsrc](https://github.com/akavel/rsrc) 自动生成, 不入库。

## 技术栈

- Go 1.26 (纯 Go, CGO_ENABLED=0)
- [modernc.org/sqlite](https://modernc.org/sqlite) — 浏览器历史 SQLite 解析
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) — 注册表 / 事件日志 (EvtQuery/ReadEventLog) / Win32 API
- [jchv/go-webview2](https://github.com/jchv/go-webview2) — WebView2 GUI (HTML/CSS/JS 经 go:embed 内嵌)
- UI: 深色科技风 (NirSoft 式信息密度 + SOC 风格配色)

## 已知限制

- LNK 解析 fork powershell, 大量 LNK 时首载较慢 (~200 个约 5-10s)
- Jump Lists 走简化 OLE 扫描, 个别条目可能遗漏
- 完整登录/登出历史需事件日志 (注册表只存最后登录快照)
- 服务全量列出 (数百条), 建议配合"可疑"列排序

## License

MIT
