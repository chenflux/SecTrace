//go:build windows

// gosectrace GUI - NirSoft 风格 + 科技感
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	webview "github.com/jchv/go-webview2"
)

const windowTitleBase = "SecTrace · 取证工具"

// guiMsg 前端消息结构
type guiMsg struct {
	Role    string     `json:"role,omitempty"`
	Type    string     `json:"type"`
	Text    string     `json:"text,omitempty"`
	Columns []string   `json:"columns,omitempty"`
	Rows    [][]string `json:"rows"`
}

func runGUI() {
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:     false,
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  windowTitleBase + " v" + version,
			Width:  1200,
			Height: 760,
			IconId: 0,
			Center: true,
		},
	})
	if w == nil {
		fmt.Println("无法创建 WebView (需要 WebView2 Runtime)")
		return
	}
	defer w.Destroy()

	bindAPI(w)
	w.SetHtml(indexHTML)
	w.Run()
}

func bindAPI(w webview.WebView) {

	w.Bind("gosectrace", func(req string) (interface{}, error) {
		var args []string
		if err := json.Unmarshal([]byte(req), &args); err != nil {
			return guiMsg{Type: "error", Text: "参数解析失败: " + err.Error()}, nil
		}
		if len(args) == 0 {
			return guiMsg{Type: "error", Text: "请指定命令"}, nil
		}
		cmd := strings.ToLower(args[0])
		cmdArgs := args[1:]

		switch cmd {
		case "browse":
			cf, browsers := parseBrowse("browse", cmdArgs)
			entries := CollectBrowseHistory(browsers, cf.N, cf.Since)
			rows := browseToRows(entries)
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("浏览器历史: %d 条", len(rows)),
				Columns: []string{"时间", "浏览器", "标题", "URL"},
				Rows:    rows,
			}, nil

		case "activity":
			collectProgress = func(name string) {
				w.Eval("window.scanProgress&&window.scanProgress(\"" + name + "\")")
			}
			rows := collectUnifiedActivity()
			collectProgress = nil
			w.Eval("window.scanDone&&window.scanDone()")
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("系统活动: %d 条", len(rows)),
				Columns: []string{"时间", "类型", "事件", "详情"},
				Rows:    rows,
			}, nil

		case "eventlog":
			// 按需加载事件日志 (最近 24h, 关键 EventID 白名单)
			// 参考 SentinelX shouldDropLowValue 思路, 不读低价值事件
			if !IsAdmin() {
				return guiMsg{
					Type: "error",
					Text: "读取事件日志需要管理员权限. 请右键 → 以管理员身份运行.",
				}, nil
			}
			evRows := readTargetedEventLogs()
			rows := make([][]string, 0, len(evRows))
			for _, e := range evRows {
				rows = append(rows, []string{
					formatActivityTime(e.Time, e.Approx), e.Type, e.Event, e.Detail,
				})
			}
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("事件日志 (24h, 关键 EID): %d 条", len(rows)),
				Columns: []string{"时间", "类型", "事件", "详情"},
				Rows:    rows,
			}, nil

		case "evl_power", "evl_network", "evl_rdp", "evl_task", "evl_ps":
			// 场景化事件日志加载
			if !IsAdmin() {
				return guiMsg{
					Type: "error",
					Text: "读取事件日志需要管理员权限. 请右键 → 以管理员身份运行.",
				}, nil
			}
			scenario := strings.TrimPrefix(cmd, "evl_")
			items := readScenarioEvents(scenario)
			rows := make([][]string, 0, len(items))
			for _, e := range items {
				rows = append(rows, []string{
					formatActivityTime(e.Time, e.Approx), e.Type, e.Event, e.Detail,
				})
			}
			scenarioNames := map[string]string{
				"power":   "开关机",
				"network": "网络连接/断开",
				"rdp":     "远程登录 (RDP)",
				"task":    "计划任务执行",
				"ps":      "PowerShell 执行",
			}
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("事件日志 / %s (24h): %d 条", scenarioNames[scenario], len(rows)),
				Columns: []string{"时间", "类型", "事件", "详情"},
				Rows:    rows,
			}, nil

		case "usb":
			rows := collectUSBToRows()
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("USB 设备: %d 条", len(rows)),
				Columns: []string{"VID", "PID", "序列号", "名称", "最近插入"},
				Rows:    rows,
			}, nil

		case "autoruns":
			rows := readAutoRuns()
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("自启动项: %d 条", len(rows)),
				Columns: []string{"启动位置", "名称", "状态", "命令", "可疑"},
				Rows:    rows,
			}, nil

		case "programs":
			rows := readInstalledPrograms()
			return guiMsg{
				Type:    "table",
				Text:    fmt.Sprintf("已安装程序: %d 条", len(rows)),
				Columns: []string{"名称", "版本", "发布者", "安装日期", "位置", "大小", "可疑"},
				Rows:    rows,
			}, nil

		default:
			return guiMsg{
				Type: "error",
				Text: fmt.Sprintf("未知命令: %s", cmd),
			}, nil
		}
	})

	w.Bind("exportData", func(req string) (interface{}, error) {
		var p struct {
			Format string `json:"format"`
			Data   string `json:"data"`
			Tab    string `json:"tab"`
		}
		if err := json.Unmarshal([]byte(req), &p); err != nil {
			return fmt.Sprintf("参数错误: %v", err), nil
		}
		desktop := getDesktopPath()
		ext := p.Format
		if ext == "json" {
			ext = "json"
		} else {
			ext = "csv"
		}
		fname := fmt.Sprintf("%s\\SecTrace_%s_%s.%s",
			desktop, sanitizeFilename(p.Tab), nowCompact(), ext)
		if err := writeBytes(fname, []byte(p.Data)); err != nil {
			return "导出失败: " + err.Error(), nil
		}
		return "已导出: " + fname, nil
	})

	w.Bind("getUIState", func(req string) (interface{}, error) {
		return readUIStateFile(), nil
	})

	w.Bind("saveUIState", func(req string) (interface{}, error) {
		saveUIStateFile(req)
		return "ok", nil
	})

	w.Bind("sysinfo", func(req string) (interface{}, error) {
		hostname, _ := getHostname()
		return map[string]string{
			"version":  version,
			"os":       "Windows",
			"admin":    boolToStr(IsAdmin()),
			"hostname": hostname,
			"pid":      fmt.Sprintf("%d", currentPID()),
		}, nil
	})
}

func sanitizeFilename(s string) string {
	r := strings.NewReplacer(":", "_", "/", "_", "\\", "_", "?", "_", "*", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return r.Replace(s)
}

func nowCompact() string {
	return fmt.Sprintf("%d%02d%02d_%02d%02d%02d",
		nowYear(), nowMonth(), nowDay(), nowHour(), nowMin(), nowSec())
}

func nowYear() int { _, m, _ := nowDate(); return m[0] }
func nowMonth() int { _, m, _ := nowDate(); return m[1] }
func nowDay() int { _, m, _ := nowDate(); return m[2] }
func nowHour() int { _, m, _ := nowDate(); return m[3] }
func nowMin() int { _, m, _ := nowDate(); return m[4] }
func nowSec() int { _, m, _ := nowDate(); return m[5] }

func nowDate() (int, [6]int, error) {
	t := timeNow()
	return 0, [6]int{t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second()}, nil
}

func getHostname() (string, error) {
	return osGetenv("COMPUTERNAME"), nil
}

func currentPID() int {
	return osGetpid()
}

func boolToStr(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

func filterBrowse(entries []BrowseEntry, kw string) []BrowseEntry {
	kw = strings.ToLower(kw)
	var out []BrowseEntry
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.URL), kw) || strings.Contains(strings.ToLower(e.Title), kw) {
			out = append(out, e)
		}
	}
	return out
}

func filterActivity(events []EventInfo, kw string) []EventInfo {
	kw = strings.ToLower(kw)
	var out []EventInfo
	for _, e := range events {
		if strings.Contains(strings.ToLower(e.Message), kw) || strings.Contains(strings.ToLower(e.Source), kw) {
			out = append(out, e)
		}
	}
	return out
}

func browseToRows(entries []BrowseEntry) [][]string {
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			e.VisitTime.Local().Format("2006-01-02 15:04:05"),
			e.Browser,
			e.Title,
			e.URL,
		})
	}
	return rows
}

func activityToRows(events []EventInfo) [][]string {
	rows := make([][]string, 0, len(events))
	for _, e := range events {
		rows = append(rows, []string{
			e.Time.Local().Format("2006-01-02 15:04:05"),
			e.LogName,
			e.Level,
			fmt.Sprintf("%d", e.EventID),
			e.Message,
		})
	}
	return rows
}

func prefetchToRows(events []EventInfo) [][]string {
	rows := make([][]string, 0, len(events))
	for _, e := range events {
		// 从 Message 解析 "执行程序: NAME" 和 路径
		msg := e.Message
		prog := msg
		if strings.HasPrefix(msg, "执行程序: ") {
			prog = strings.TrimPrefix(msg, "执行程序: ")
		}
		rows = append(rows, []string{
			e.Time.Local().Format("2006-01-02 15:04:05"),
			prog,
			`C:\Windows\Prefetch\` + prog + "-????????.pf",
		})
	}
	return rows
}

func recentToRows(events []EventInfo) [][]string {
	rows := make([][]string, 0, len(events))
	for _, e := range events {
		// Message: "最近访问 [name]: path"
		name, path := "", e.Message
		if i := strings.Index(e.Message, "]: "); i > 0 {
			name = e.Message[len("最近访问 ["):i]
			path = e.Message[i+3:]
		}
		rows = append(rows, []string{
			e.Source,
			name,
			path,
		})
	}
	return rows
}

// ActivityItem 活动痕迹统一结构
// Approx=true 表示时间不是事件本身的精确时间戳, 而是注册表键
// LastWriteTime 之类的近似时间, 前端显示为 "≈时间" 提醒分析人员
type ActivityItem struct {
	Time   time.Time
	Approx bool
	Type   string
	Event  string
	Detail string
}

// formatActivityTime 格式化活动时间:
//   - 精确时间戳: "2026-10-14 09:00:00"
//   - 近似时间 (键写入时间等): "≈2026-10-14 09:00:00"
//   - 无时间: "-"
func formatActivityTime(t time.Time, approx bool) string {
	if t.IsZero() {
		return "-"
	}
	s := t.Local().Format("2006-01-02 15:04:05")
	if approx {
		return "≈" + s
	}
	return s
}

// collectUnifiedActivity 收集用户行为痕迹 (15 类, 不含 Windows 事件日志):
//   1. Prefetch       - 程序执行记录 (C:\Windows\Prefetch)
//   2. 最近文件       - HKCU\...\RecentDocs
//   3. BSOD           - C:\Windows\Minidump
//   4. BAM            - HKLM\...\bam\State\UserSettings\<SID>
//   5. UserAssist     - HKCU\...\Explorer\UserAssist (ROT13 解码)
//   6. LNK            - %APPDATA%\Microsoft\Windows\Recent\*.lnk
//   7. JumpList       - %APPDATA%\...\Recent\AutomaticDestinations\*.automaticDestinations-ms
//   8. RunMRU         - HKCU\...\Explorer\RunMRU
//   9. TypedPaths/URLs - 用户键入的路径/URL
//  10. 计划任务       - C:\Windows\System32\Tasks\*.xml
//  11. 回收站         - C:\$Recycle.Bin\<SID>\$I* (元数据, 不含内容)
//  12. 网络           - NetworkList\Profiles + Signatures (有线/无线连接)
//  13. 电源           - Watchdog\Display + GetTickCount64 (开关机)
//  14. 用户           - ProfileList + LogonUI (登录信息)
//
// 故意不包含 Windows 事件日志, 噪声太大 (特别是安全日志的
// AuditSuccess). 真正的事件分析请用 `gosectrace.exe activity -sources event,...`
// 或专门的 EVTX 工具.
//
// 故意不包含 Windows 事件日志, 噪声太大 (特别是安全日志的
// AuditSuccess). 真正的事件分析请用 `gosectrace.exe activity -sources event,...`
// 或专门的 EVTX 工具.
//
// 字段: [时间, 类型, 事件, 详情]

type bsodItem struct {
	time   time.Time
	detail string
}

// readBSODInternal 读 Minidump 目录, 返回最近 5 个 .dmp
func readBSODInternal() []bsodItem {
	var out []bsodItem
	dir := `C:\Windows\Minidump`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	type fentry struct {
		name string
		mod  time.Time
	}
	var files []fentry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
			continue
		}
		fi, _ := e.Info()
		if fi == nil {
			continue
		}
		files = append(files, fentry{e.Name(), fi.ModTime()})
	}
	// 按时间倒序, 取前 5
	sort.Slice(files, func(i, j int) bool {
		return files[i].mod.After(files[j].mod)
	})
	for i := 0; i < len(files) && i < 5; i++ {
		out = append(out, bsodItem{files[i].mod, "转储文件: " + files[i].name})
	}
	return out
}
