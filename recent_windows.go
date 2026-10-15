//go:build windows

package main

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

func readRecentDocs() []EventInfo {
	paths := []string{
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xlsx`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.py`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.exe`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.zip`,
		`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentFolderNames`,
	}
	var events []EventInfo
	for _, p := range paths {
		events = append(events, readRegistryEnum(registry.CURRENT_USER, p)...)
	}
	return events
}

func readRegistryEnum(root registry.Key, subPath string) []EventInfo {
	var events []EventInfo
	k, err := registry.OpenKey(root, subPath, registry.READ)
	if err != nil {
		return events
	}
	defer k.Close()

	// 注册表值本身无时间戳, 用键的 LastWriteTime 作为近似时间
	// (表示该扩展名子键最近一次被写入 = 最近一次访问该类型文件的时间)
	var keyTime time.Time
	if stat, err := k.Stat(); err == nil {
		keyTime = stat.ModTime()
	}

	names, err := k.ReadValueNames(20)
	if err != nil {
		return events
	}
	for _, name := range names {
		if name == "MRUListEx" {
			continue
		}
		// 先按 string 读, 失败回退 binary
		val, valType, err := k.GetStringValue(name)
		if err != nil {
			data, vt, err2 := k.GetBinaryValue(name)
			if err2 != nil {
				continue
			}
			valType = vt
			val = decodeUTF16LE(data)
		}
		_ = valType
		val = CleanText(val)
		if val == "" {
			continue
		}
		events = append(events, EventInfo{
			LogName: "RecentDocs",
			Time:    keyTime,
			Level:   "Info",
			Source:  "Explorer",
			EventID: 0,
			Message: fmt.Sprintf("最近访问 [%s]: %s", name, val),
		})
	}
	return events
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return syscall.UTF16ToString(u16)
}
