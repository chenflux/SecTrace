// gosectrace - Go 版活动痕迹 + 浏览历史查看器
// 集成 browsinghistoryview + lastActivityView 功能
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var version = "1.0.0"

type CommonFlags struct {
	N       int
	Since   time.Time
	Search  string
	OutFile string
	Format  Format
}

func main() {
	if len(os.Args) < 2 {
		// 无参数默认启动 GUI
		runGUI()
		return
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "browse":
		runBrowse(args)
	case "activity":
		runActivity(args)
	case "eventlog":
		runEventLog(args)
	case "autoruns":
		rows := readAutoRuns()
		fmt.Printf("自启动项: %d 条\n\n", len(rows))
		for _, r := range rows {
			fmt.Printf("%-22s | %-35s | %s %s\n", r[0], r[1], r[2], r[3])
		}
	case "programs":
		rows := readInstalledPrograms()
		fmt.Printf("已安装程序: %d 条\n\n", len(rows))
		for _, r := range rows {
			fmt.Printf("%-45s | %-12s | %-25s | %s %s\n", r[0], r[1], r[2], r[3], r[6])
		}
	case "all":
		runAll(args)
	case "gui":
		runGUI()
	case "version", "-v", "--version":
		fmt.Printf("gosectrace v%s\n", version)
	case "help", "-h", "--help", "/?":
		usage()
	default:
		fmt.Printf("未知命令: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`gosectrace - 系统活动痕迹 + 浏览器历史取证工具 (Go 版)

用法:
  gosectrace gui                  启动 GUI 界面 (仿微信风格, 默认)
  gosectrace browse     [选项]   浏览器历史 (Chrome/Edge/Firefox/Brave)
  gosectrace activity   [选项]   系统活动 (事件日志/Prefetch/最近文件/BSOD)
  gosectrace all        [选项]   全部
  gosectrace version              版本

通用选项:
  -n <数量>              限制条数 (默认 200)
  -since <时长>          只显示最近, 如 24h / 7d / 30m
  -search <关键字>        关键字过滤
  -o <文件>              导出文件
  -f csv|json|text       输出格式 (默认 text, 导出时按扩展名自动判断)
  -browsers chrome,edge  指定浏览器 (逗号分隔)         [browse]
  -sources event,prefetch,...  指定活动来源            [activity]

示例:
  gosectrace browse
  gosectrace browse -n 50 -since 24h
  gosectrace browse -browsers chrome,edge -o history.csv
  gosectrace activity -sources event,prefetch
  gosectrace activity -search "登录"
  gosectrace all -o report -f json`)
}

// parseBrowse 注册并解析 browse 子命令的所有 flag
func parseBrowse(name string, args []string) (CommonFlags, []string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cf := CommonFlags{N: 200, Format: FormatText}
	fs.IntVar(&cf.N, "n", 200, "限制条数")
	sinceStr := fs.String("since", "", "最近时长 (如 24h / 7d)")
	fs.StringVar(&cf.Search, "search", "", "关键字过滤")
	fs.StringVar(&cf.OutFile, "o", "", "导出文件")
	formatStr := fs.String("f", "text", "输出格式 (text/csv/json)")
	browsersStr := fs.String("browsers", "", "指定浏览器 (逗号分隔)")
	fs.Parse(args)
	if *sinceStr != "" {
		if d, err := time.ParseDuration(*sinceStr); err == nil {
			cf.Since = time.Now().Add(-d)
		}
	}
	cf.Format = parseFormat(*formatStr)
	var browsers []string
	if *browsersStr != "" {
		browsers = strings.Split(*browsersStr, ",")
	}
	return cf, browsers
}

func parseActivity(name string, args []string) (CommonFlags, []string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cf := CommonFlags{N: 200, Format: FormatText}
	fs.IntVar(&cf.N, "n", 200, "限制条数")
	sinceStr := fs.String("since", "", "最近时长 (如 24h / 7d)")
	fs.StringVar(&cf.Search, "search", "", "关键字过滤")
	fs.StringVar(&cf.OutFile, "o", "", "导出文件")
	formatStr := fs.String("f", "text", "输出格式 (text/csv/json)")
	sourcesStr := fs.String("sources", "all", "活动来源 (all/event/prefetch/recent/bsod)")
	fs.Parse(args)
	if *sinceStr != "" {
		if d, err := time.ParseDuration(*sinceStr); err == nil {
			cf.Since = time.Now().Add(-d)
		}
	}
	cf.Format = parseFormat(*formatStr)
	var sources []string
	if *sourcesStr != "" && *sourcesStr != "all" {
		sources = strings.Split(*sourcesStr, ",")
	}
	return cf, sources
}

func runBrowse(args []string) {
	cf, browsers := parseBrowse("browse", args)

	fmt.Println("=== 浏览器历史收集 ===")
	fmt.Printf("  限制: %d 条  搜索: %q  浏览器: %v\n", cf.N, cf.Search, browsers)
	entries := CollectBrowseHistory(browsers, cf.N, cf.Since)
	if cf.Search != "" {
		var filtered []BrowseEntry
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.URL), strings.ToLower(cf.Search)) ||
				strings.Contains(strings.ToLower(e.Title), strings.ToLower(cf.Search)) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	headers := []string{"时间", "浏览器", "标题", "URL"}
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			e.VisitTime.Local().Format("2006-01-02 15:04:05"),
			e.Browser,
			e.Title,
			e.URL,
		})
	}
	if cf.OutFile != "" {
		format := cf.Format
		if strings.HasSuffix(cf.OutFile, ".json") {
			format = FormatJSON
		} else if strings.HasSuffix(cf.OutFile, ".csv") {
			format = FormatCSV
		}
		export(cf.OutFile, format, headers, rows)
	} else {
		printTable(headers, rows)
		fmt.Printf("\n共 %d 条\n", len(entries))
	}
}

func runActivity(args []string) {
	cf, _ := parseActivity("activity", args)

	fmt.Println("=== 系统活动痕迹收集 ===")
	// 与 GUI 统一口径: 15+ 类痕迹源合并时间线 (不含事件日志, 用 eventlog 子命令)
	rows := collectUnifiedActivity()
	if cf.N > 0 && len(rows) > cf.N {
		rows = rows[:cf.N]
	}
	if cf.Search != "" {
		kw := strings.ToLower(cf.Search)
		var filtered [][]string
		for _, r := range rows {
			if strings.Contains(strings.ToLower(r[2]), kw) ||
				strings.Contains(strings.ToLower(r[3]), kw) ||
				strings.Contains(strings.ToLower(r[1]), kw) {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	headers := []string{"时间", "类型", "事件", "详情"}
	if cf.OutFile != "" {
		format := cf.Format
		if strings.HasSuffix(cf.OutFile, ".json") {
			format = FormatJSON
		} else if strings.HasSuffix(cf.OutFile, ".csv") {
			format = FormatCSV
		}
		export(cf.OutFile, format, headers, rows)
	} else {
		printTable(headers, rows)
		fmt.Printf("\n共 %d 条\n", len(rows))
	}
}

func runAll(args []string) {
	runBrowse(args)
	fmt.Println()
	runActivity(args)
}

func runEventLog(args []string) {
	scenario := ""
	if len(args) > 0 {
		scenario = args[0]
	}
	if scenario == "" {
		// 默认: 开关机 + 网络 + RDP + 任务 全部
		for _, s := range []string{"power", "network", "rdp", "task"} {
			runEventLog([]string{s})
		}
		return
	}
	if !IsAdmin() {
		fmt.Println("错误: 读取事件日志需要管理员权限. 请右键 → 以管理员身份运行")
		return
	}
	items := readScenarioEvents(scenario)
	scenarioNames := map[string]string{
		"power":   "开关机",
		"network": "网络连接/断开",
		"rdp":     "远程登录 (RDP)",
		"task":    "计划任务执行",
	}
	fmt.Printf("=== 事件日志 / %s (24h) ===\n", scenarioNames[scenario])
	fmt.Printf("  共 %d 条\n\n", len(items))
	for _, e := range items {
		timeStr := "-"
		if !e.Time.IsZero() {
			timeStr = e.Time.Local().Format("2006-01-02 15:04:05")
		}
		detail := e.Detail
		if len(detail) > 120 {
			detail = detail[:117] + "..."
		}
		fmt.Printf("%s  %-8s  %s\n  └─ %s\n",
			timeStr, e.Type, e.Event, detail)
	}
}

func export(path string, format Format, headers []string, rows [][]string) {
	var err error
	switch format {
	case FormatCSV:
		err = exportCSV(path, headers, rows)
	case FormatJSON:
		err = exportJSON(path, rows, headers)
	default:
		err = exportTab(path, headers, rows)
	}
	if err != nil {
		FatalError("导出失败: %v", err)
	}
	abs, _ := filepathAbs()
	fmt.Printf("已导出 %d 条 -> %s/%s\n", len(rows), abs, path)
}

func filepathAbs() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return wd, nil
}
