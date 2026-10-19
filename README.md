# SecTrace

Windows 应急取证辅助工具 (Go + WebView2, 单文件 GUI, 无外部依赖)。

## 功能

### GUI (双击运行, 默认启动)

| 视图 | 数据源 |
|---|---|
| **浏览器历史** | Chrome / Edge / Firefox / Brave / Vivaldi (Local State 全 Profile 枚举, WAL 伴随复制防丢, visits 表 JOIN 完整访问序列) |
| **系统活动** | 18 类痕迹并发收集 (见下) |
| **USB 设备** | USBSTOR 注册表 (VID/PID/序列号/名称/最近插入时间) |
| **自启动项** | Run/RunOnce(8处)、Winlogon、AppInit_DLLs、IFEO、Active Setup、BootExecute、服务/驱动(**含 svchost ServiceDll 载荷**)、启动文件夹; **状态列**(StartupApproved 启用/禁用), 可疑启发式标记 |
| **已安装程序** | 3 个 Uninstall 位置, 远控工具黑名单标记 (TeamViewer/AnyDesk/向日葵/RustDesk 等 24 关键词) |

### 系统活动 (18 类痕迹源, 并发收集)

- **程序执行历史**: Prefetch (XPRESS-Huffman 解压→SCCA 内嵌运行时间+次数; Win11 24H2 v31 优雅回退 mtime) / **Shimcache** (AppCompatCache Win10 x64 二进制解析) / **Amcache** (RegLoadKey 挂载 hve, SeRestore 提权, 用完卸载不留痕) / BAM / UserAssist
- **文件访问历史**: LNK (**原生 MS-SHLLINK 二进制解析**, 含目标三时间戳/文件大小/卷序列号, 零 PowerShell fork) / Jump Lists / 最近文档 / 回收站 (**全盘固定盘**枚举, $I v1/v2 版本判别) / **MOTW** (Zone.Identifier ADS 扫描 Downloads/Desktop, 标记文件来源互联网/内网)
- **键入历史**: RunMRU / TypedPaths / TypedURLs
- **系统事件**: 开关机 (Watchdog + GetTickCount64) / 网络连接 (NetworkList) / 登录 (ProfileList + LogonUI) / 计划任务 (**递归** WalkDir 含子目录)
- **故障事件**: BSOD Minidump
- **事件日志按需加载** (需管理员, 24h, **XPath 服务端 EID 过滤** + 客户端兜底): 开关机 / 网络接入断开 / 登录登出(含 RDP) / 计划任务执行 / **PowerShell 脚本块**(4103/4104, 挂在"程序执行"子标签)
- **SID 翻译**: 事件详情中的 S-1-5-21-... 自动翻译为 DOMAIN\user (LookupAccountSid + 常见 SID 静态表)

### 取证时间可信度

- 精确时间戳: 直接显示
- 近似时间 (注册表键 LastWriteTime / 文件 mtime): `≈` 前缀标记
- 无时间: 显示 `-` (排序沉底), **绝不**用"当前时间"冒充事件时间

### 表格交互

列宽拖动 (双击自适应, **跨启动持久化**至 %APPDATA%\SecTrace\ui.json) / 表头排序 / 实时关键字过滤 / **只看可疑**一键过滤 (自启动项/已安装程序页) / 拖选复制 / 双击行复制 / CSV / JSON 导出 / **收集进度实时反馈**

## 使用

```
SecTrace.exe                    # GUI (默认)
SecTrace.exe browse -n 50       # CLI: 浏览器历史
SecTrace.exe activity           # CLI: 系统活动 (与 GUI 统一口径)
SecTrace.exe eventlog rdp       # CLI: 事件日志场景 (power/network/rdp/task/ps)
SecTrace.exe autoruns           # CLI: 自启动项
SecTrace.exe programs           # CLI: 已安装程序
```

> 事件日志相关功能需要管理员权限 (右键 → 以管理员身份运行)。
> 需要 WebView2 Runtime (Windows 10 1803+ 一般自带)。

## 编译

```bat
build.bat
```

自动生成 3 个架构到 `outputs/`:

| 文件 | 架构 |
|---|---|
| SecTrace_windows_x86.exe | 386 (32 位) |
| SecTrace_windows_x64.exe | amd64 (64 位) |
| SecTrace_windows_arm64.exe | ARM64 (Surface / ARM PC) |

> Go 官方不支持 windows/arm 32 位, 故无此目标。

图标资源 (`rsrc_*_windows_*.syso`) 由脚本调用 [akavel/rsrc](https://github.com/akavel/rsrc) 自动生成, 不入库。
版本号由 `-X main.version` 注入 (日期 + git 短 SHA)。

## 测试

```bash
go test -count=1 ./...
```

解析器单元测试覆盖: $I 回收站 v1/v2、LNK 头/LinkInfo/字符串数据 (MS-SHLLINK fixture)、XPRESS-Huffman (ntdll RtlCompressBuffer 回环)、事件 XML (单双引号 + 位置型 Data)、SID 翻译、自启动可疑启发式。

## 技术栈

- Go 1.26 (纯 Go, CGO_ENABLED=0)
- [modernc.org/sqlite](https://modernc.org/sqlite) — 浏览器历史 SQLite 解析
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) — 注册表 / 事件日志 (EvtQuery + XPath 服务端过滤) / Win32 API
- [jchv/go-webview2](https://github.com/jchv/go-webview2) — WebView2 GUI (HTML/CSS/JS 经 go:embed 内嵌)
- UI: 深色科技风 (NirSoft 式信息密度 + SOC 风格配色)

## 已知限制

- **Win11 24H2 Prefetch**: SCCA v31 布局变更且未公开文档, 深度解析回退到文件 mtime (≈ 标记)
- Jump Lists 走简化 OLE 扫描, 个别条目可能遗漏
- 完整登录/登出历史需事件日志 (注册表只存最后登录快照)
- Amcache 需 SeRestorePrivilege (普通用户进程仅显示挂载失败提示)
- 事件日志读取上限 5000 条/渠道 (忙日志 24h 可能截断)

## License

GPL-2.0 (见 [LICENSE](LICENSE))
