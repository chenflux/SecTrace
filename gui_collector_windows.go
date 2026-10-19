//go:build windows

// gui_collector.go — 统一活动收集 (并发版)
// 18 类痕迹源并发采集 (WaitGroup), 可选进度回调 (GUI 经 Eval 推送)

package main

import (
	"sort"
	"sync"
	"time"
)

// collectProgress 进度回调 (nil = 无进度); 参数: "源名✓" / "源名✗"
var collectProgress func(string)

type namedCollector struct {
	name string
	fn   func() []ActivityItem
}

// activityCollectors 全部痕迹源 (顺序 = 进度展示顺序)
func activityCollectors() []namedCollector {
	return []namedCollector{
		{"Prefetch", func() []ActivityItem { return readPrefetchDeep() }},
		{"Shimcache", func() []ActivityItem { return readShimcache() }},
		{"Amcache", func() []ActivityItem { return readAmcache() }},
		{"MOTW", func() []ActivityItem { return readMOTW() }},
		{"BAM", func() []ActivityItem { return readBAM() }},
		{"UserAssist", func() []ActivityItem { return readUserAssist() }},
		{"LNK", func() []ActivityItem { return readLNKs() }},
		{"JumpList", func() []ActivityItem { return readJumpLists() }},
		{"RecentDocs", readRecentDocsItems},
		{"RunMRU", func() []ActivityItem { return readRunMRU() }},
		{"TypedPaths", func() []ActivityItem { return readTypedPaths() }},
		{"TypedURLs", func() []ActivityItem { return readTypedURLs() }},
		{"Tasks", func() []ActivityItem { return readScheduledTasks() }},
		{"RecycleBin", func() []ActivityItem { return readRecycleBin() }},
		{"Network", func() []ActivityItem {
			return append(readNetworkProfiles(), readWirelessSignatures()...)
		}},
		{"Power", func() []ActivityItem { return readPowerEvents() }},
		{"Sessions", func() []ActivityItem { return readUserSessions() }},
		{"BSOD", readBSODItems},
	}
}

// readRecentDocsItems RecentDocs → ActivityItem (时间为键 LastWriteTime ≈)
func readRecentDocsItems() []ActivityItem {
	var out []ActivityItem
	for _, e := range readRecentDocs() {
		name, path := "", e.Message
		if i := indexStr(e.Message, "]: "); i > 0 {
			name = e.Message[len("最近访问 ["):i]
			path = e.Message[i+3:]
		}
		out = append(out, ActivityItem{
			Time: e.Time, Approx: !e.Time.IsZero(),
			Type:   "最近访问",
			Event:  "文件/文件夹: " + name,
			Detail: path + " | 时间=键最后写入(近似)",
		})
	}
	if len(out) == 0 {
		out = append(out, ActivityItem{Type: "最近访问", Event: "无最近访问记录"})
	}
	return out
}

// readBSODItems BSOD → ActivityItem
func readBSODItems() []ActivityItem {
	var out []ActivityItem
	for _, b := range readBSODInternal() {
		out = append(out, ActivityItem{
			Time: b.time, Type: "系统错误",
			Event: "蓝屏崩溃(BSOD)", Detail: b.detail,
		})
	}
	return out
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// collectUnifiedActivity 并发收集全部痕迹 → [时间,类型,事件,详情]
func collectUnifiedActivity() [][]string {
	collectors := activityCollectors()
	results := make([][]ActivityItem, len(collectors))

	var wg sync.WaitGroup
	for i, c := range collectors {
		wg.Add(1)
		go func(idx int, name string, fn func() []ActivityItem) {
			defer wg.Done()
			results[idx] = fn()
			if collectProgress != nil {
				collectProgress(name)
			}
		}(i, c.name, c.fn)
	}
	wg.Wait()

	const tsFormat = "2006-01-02 15:04:05"
	type row struct {
		time time.Time
		cols []string
	}
	var rows []row
	for i, items := range results {
		label := collectors[i].name
		_ = label
		for _, it := range items {
			rows = append(rows, row{it.Time, []string{
				formatActivityTime(it.Time, it.Approx), it.Type, it.Event, it.Detail,
			}})
		}
	}

	sort.SliceStable(rows, func(i, j int) bool { return rows[i].time.After(rows[j].time) })

	// 去重 (同时间同类型同事件同详情)
	seen := make(map[string]bool)
	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		key := r.cols[0] + "|" + r.cols[1] + "|" + r.cols[2] + "|" + r.cols[3]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r.cols)
	}
	return out
}
