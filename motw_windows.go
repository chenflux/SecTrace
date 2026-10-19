//go:build windows

// MOTW (Mark of the Web) 扫描
// 枚举 Downloads / Desktop 顶层文件的 Zone.Identifier ADS,
// 标记文件来源 (3=互联网 4=受限 2=内网 1=本地 Intranet)

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var zoneNames = map[string]string{
	"0": "本机",
	"1": "本地 Intranet",
	"2": "受信任站点",
	"3": "互联网",
	"4": "受限站点",
}

// readZoneIdentifier 读取文件 ADS: Zone.Identifier
func readZoneIdentifier(path string) (zone string, host string, ok bool) {
	data, err := os.ReadFile(path + ":Zone.Identifier:$DATA")
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ZoneId=") {
			zone = strings.TrimPrefix(line, "ZoneId=")
		}
		if strings.HasPrefix(line, "HostUrl=") {
			host = strings.TrimPrefix(line, "HostUrl=")
			if len(host) > 120 {
				host = host[:120] + "..."
			}
		}
	}
	return zone, host, zone != ""
}

// readMOTW 扫描下载标记
func readMOTW() []ActivityItem {
	var out []ActivityItem
	userHome, _ := os.UserHomeDir()
	dirs := []string{
		filepath.Join(userHome, "Downloads"),
		filepath.Join(userHome, "Desktop"),
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		count := 0
		for _, e := range entries {
			if count >= 300 {
				break
			}
			if e.IsDir() {
				continue
			}
			count++
			p := filepath.Join(d, e.Name())
			zone, host, ok := readZoneIdentifier(p)
			if !ok {
				continue
			}
			zoneName := zoneNames[zone]
			if zoneName == "" {
				zoneName = "Zone " + zone
			}
			detail := fmt.Sprintf("来源: %s | 文件: %s", zoneName, p)
			if host != "" {
				detail += " | URL: " + host
			}
			fi, _ := e.Info()
			item := ActivityItem{
				Type:   "MOTW",
				Event:  "下载文件: " + e.Name(),
				Detail: detail,
			}
			if fi != nil {
				item.Time = fi.ModTime()
			}
			out = append(out, item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

var _ = windows.UTF16PtrFromString
var _ unsafe.Pointer
