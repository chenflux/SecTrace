package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CollectActivity 收集所有活动痕迹
// sources: "all"/"event"/"prefetch"/"recent"/"bsod"
func CollectActivity(sources []string, limit int) []EventInfo {
	all := map[string]bool{}
	if len(sources) == 0 || contains(sources, "all") {
		all["event"] = true
		all["prefetch"] = true
		all["recent"] = true
		all["bsod"] = true
	} else {
		for _, s := range sources {
			all[strings.ToLower(s)] = true
		}
	}
	var events []EventInfo
	// 1. 事件日志
	if all["event"] {
		PrintSection("[1/4] 读取事件日志 (System/Application/Security)")
		needAdmin := true
		logs := []struct {
			Name string
			N    int
		}{
			{"System", 50},
			{"Application", 30},
			{"Security", 20},
		}
		if !IsAdmin() && needAdmin {
			fmt.Println("[!] 提示: 非管理员, 部分日志 (Security) 可能读不到")
		}
		for _, l := range logs {
			ev, err := readEventLog(l.Name, l.N)
			if err != nil {
				fmt.Printf("  [!] %s: %v\n", l.Name, err)
				continue
			}
			fmt.Printf("  %s: %d 条\n", l.Name, len(ev))
			events = append(events, ev...)
		}
	}

	// 2. Prefetch
	if all["prefetch"] {
		PrintSection("[2/4] 读取 Prefetch (程序运行记录)")
		events = append(events, readPrefetch(30)...)
	}

	// 3. 最近文件
	if all["recent"] {
		PrintSection("[3/4] 读取最近文档 (注册表)")
		events = append(events, readRecentDocs()...)
	}

	// 4. 蓝屏
	if all["bsod"] {
		PrintSection("[4/4] 读取蓝屏转储 (Minidump)")
		events = append(events, readBSOD()...)
	}

	// 按时间倒序
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Time.After(events[j].Time)
	})
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events
}

var prefetchPattern = regexp.MustCompile(`^(.+?)-[A-F0-9]{8}\.pf$`)

func readPrefetch(n int) []EventInfo {
	var events []EventInfo
	dir := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []EventInfo{{
			LogName: "Prefetch",
			Time:    time.Now(),
			Level:   "Warn",
			Source:  "Prefetch",
			Message: fmt.Sprintf("无法读取 %s: %v (需管理员)", dir, err),
		}}
	}
	count := 0
	for _, e := range entries {
		if n > 0 && count >= n {
			break
		}
		if e.IsDir() {
			continue
		}
		m := prefetchPattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		full := filepath.Join(dir, e.Name())
		fi, err := os.Stat(full)
		if err != nil {
			continue
		}
		name := CleanText(strings.ReplaceAll(strings.ReplaceAll(m[1], "~", ""), "_", " "))
		events = append(events, EventInfo{
			LogName: "Prefetch",
			Time:    fi.ModTime(),
			Level:   "Info",
			Source:  "Prefetch",
			EventID: 0,
			Message: fmt.Sprintf("执行程序: %s", name),
		})
		count++
	}
	fmt.Printf("  找到 %d 条 Prefetch 记录\n", count)
	return events
}

func readBSOD() []EventInfo {
	var events []EventInfo
	dir := `C:\Windows\Minidump`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []EventInfo{{
			LogName: "BSOD",
			Time:    time.Now(),
			Level:   "Info",
			Source:  "Minidump",
			Message: fmt.Sprintf("未启用蓝屏转储 (%v)", err),
		}}
	}
	count := 0
	for _, e := range entries {
		if count >= 5 {
			break
		}
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		fi, _ := os.Stat(full)
		events = append(events, EventInfo{
			LogName: "BSOD",
			Time:    fi.ModTime(),
			Level:   "Error",
			Source:  "BSOD",
			EventID: 0,
			Message: fmt.Sprintf("蓝屏转储: %s", e.Name()),
		})
		count++
	}
	fmt.Printf("  找到 %d 个 Minidump 文件\n", count)
	return events
}

// PrintActivityTable 打印活动表格
func PrintActivityTable(events []EventInfo) {
	headers := []string{"时间", "来源", "级别", "事件", "详情"}
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
	printTable(headers, rows)
	fmt.Printf("\n共 %d 条\n", len(events))
}
