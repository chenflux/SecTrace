//go:build windows

// 综合事件日志读取 (GUI "eventlog" 命令)
// 复用场景化读取: power + network + rdp + task + ps 全部场景合并

package main

// readTargetedEventLogs 综合 24h 关键 EID 读取 (按需, 需管理员)
func readTargetedEventLogs() []ActivityItem {
	var out []ActivityItem
	for _, s := range []string{"power", "network", "rdp", "task", "ps"} {
		out = append(out, readScenarioEvents(s)...)
	}
	return out
}
