//go:build windows

// 开关机/休眠/唤醒记录
// 来源:
//   - HKLM\SYSTEM\CurrentControlSet\Control\Watchdog\Display (上次关机/启动 FILETIME)
//   - kernel32!GetTickCount64 (计算当前系统启动时间)
//   - HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PowerState (休眠状态)
//   - HKLM\...\WindowsUpdate\Auto Update\Results\Install (最近更新时间)
//
// 注: 完整历史开关机需要事件日志 6005/6006/6008/1074, 但用户禁用事件日志.
// 这里只能给"最近一次" + 当前运行状态.

package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64    = kernel32.NewProc("GetTickCount64")
	procGetSystemTimes    = kernel32.NewProc("GetSystemTimes")
)

type systemTimes struct {
	Idle   syscall.Filetime
	Kernel syscall.Filetime
	User   syscall.Filetime
}

// readPowerEvents 读电源相关事件
func readPowerEvents() []ActivityItem {
	var out []ActivityItem

	// 1) Watchdog\Display (上次启动 + 上次关机)
	wd, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Watchdog\Display`, registry.READ)
	if err == nil {
		// LastBootTime - 8 字节 FILETIME
		if data, _, err := wd.GetBinaryValue("LastBootTime"); err == nil && len(data) >= 8 {
			ft := binary.LittleEndian.Uint64(data[0:8])
			t := fileTimeToTime(ft)
			if !t.IsZero() {
				out = append(out, ActivityItem{
					Time:   t,
					Approx: false,
					Type:   "电源",
					Event:  "上次启动",
					Detail: "Watchdog 记录 (注册表键值, 较精确)",
				})
			}
		}
		// LastBootShutdownTime - 8 字节 FILETIME
		if data, _, err := wd.GetBinaryValue("LastBootShutdownTime"); err == nil && len(data) >= 8 {
			ft := binary.LittleEndian.Uint64(data[0:8])
			t := fileTimeToTime(ft)
			if !t.IsZero() {
				out = append(out, ActivityItem{
					Time:   t,
					Approx: false,
					Type:   "电源",
					Event:  "上次关机",
					Detail: "Watchdog 记录 (注册表键值, 较精确)",
				})
			}
		}
		wd.Close()
	}

	// 2) 当前启动时间 (用 GetTickCount64 反推)
	if bootTime, ok := getCurrentBootTime(); ok {
		out = append(out, ActivityItem{
			Time:   bootTime,
			Approx: false,
			Type:   "电源",
			Event:  "本次启动",
			Detail: fmt.Sprintf("已运行 %s (由 GetTickCount64 推算)", formatDuration(time.Since(bootTime))),
		})
	}

	// 3) 休眠状态
	sm, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager`, registry.READ)
	if err == nil {
		_ = sm
		sm.Close()
	}

	// 4) 最近 Windows Update 安装时间
	wu, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`, registry.READ)
	if err == nil {
		// 列出子键, 每个子键是一次安装
		subKeys, _ := wu.ReadSubKeyNames(20)
		for _, sk := range subKeys {
			ik, err := registry.OpenKey(wu, sk, registry.READ)
			if err != nil {
				continue
			}
			stat, _ := ik.Stat()
			if stat != nil {
				out = append(out, ActivityItem{
					Time:   stat.ModTime(),
					Approx: false,
					Type:   "电源",
					Event:  "Windows Update 安装",
					Detail: fmt.Sprintf("子键: %s (键 LastWriteTime)", sk),
				})
			}
			ik.Close()
		}
		wu.Close()
	}

	return out
}

// getCurrentBootTime 用 GetTickCount64 反推当前系统启动时间
func getCurrentBootTime() (time.Time, bool) {
	r1, _, _ := procGetTickCount64.Call()
	uptimeMs := int64(r1) & 0x7FFFFFFFFFFFFFFF
	if uptimeMs <= 0 {
		return time.Time{}, false
	}
	bootTime := timeNow().Add(-time.Duration(uptimeMs) * time.Millisecond)
	return bootTime, true
}

// formatDuration 把 time.Duration 格式化为 "X小时Y分" 或 "X天Y小时"
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "未知"
	}
	total := int(d.Seconds())
	days := total / 86400
	total %= 86400
	hours := total / 3600
	total %= 3600
	mins := total / 60
	if days > 0 {
		return fmt.Sprintf("%d天%d小时%d分", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%d小时%d分", hours, mins)
	}
	return fmt.Sprintf("%d分%d秒", mins, total%60)
}
