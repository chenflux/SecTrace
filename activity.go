package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// 注: 事件日志类痕迹请用 eventlog 子命令 / GUI 场景加载 (EID 白名单, 噪声可控)
// 本文件只保留 Prefetch 基础解析 (文件级); 深度解析 (内嵌运行时间/次数) 见
// prefetch_windows.go (Phase 2)

var prefetchPattern = regexp.MustCompile(`^(.+?)-[A-F0-9]{8}\.pf$`)

// readPrefetch 列举 Prefetch 文件 (文件名 + mtime)
// n<=0 表示全部
func readPrefetch(n int) []EventInfo {
	var events []EventInfo
	dir := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(dir)
	if err != nil {
		// 占位提示: 不伪造时间, 显示 "-"
		return []EventInfo{{
			LogName: "Prefetch",
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
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	return events
}
