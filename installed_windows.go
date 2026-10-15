//go:build windows

// 已安装程序清单 (3 个 Uninstall 注册表位置)
// 重点: 远程控制工具黑名单标记 (IR 排查攻击者投放的 RAT)

package main

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ratKeywords 远程控制/远维工具关键词 (应急响应重点排查)
var ratKeywords = []string{
	"teamviewer", "anydesk", "vnc", "radmin", "ammyy", "ultraviewer",
	"splashtop", "gotoassist", "logmein", "dwservice", "rustdesk",
	"todesk", "向日葵", "sunlogin", "aweray", "awesun",
	"remote utilities", "airdroid", "desktopnow", "rmt远程", "novnc",
	"parsec", "rustdesk", "meshagent", "screenconnect", "connectwise",
}

func readInstalledPrograms() [][]string {
	type prog struct {
		Name, Version, Publisher, Date, Location, Size, Suspicious string
	}
	var progs []prog

	bases := []struct {
		root registry.Key
		path string
		tag  string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, ""},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, " (32位)"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, " (用户)"},
	}
	for _, b := range bases {
		k, err := registry.OpenKey(b.root, b.path, registry.READ)
		if err != nil {
			continue
		}
		subs, _ := k.ReadSubKeyNames(1500)
		for _, s := range subs {
			sk, err := registry.OpenKey(k, s, registry.READ)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			if name == "" {
				sk.Close()
				continue
			}
			// 系统组件不显示 (控制面板同款行为)
			if sc, _, e := sk.GetIntegerValue("SystemComponent"); e == nil && sc == 1 {
				sk.Close()
				continue
			}
			ver, _, _ := sk.GetStringValue("DisplayVersion")
			pub, _, _ := sk.GetStringValue("Publisher")
			date, _, _ := sk.GetStringValue("InstallDate")
			if len(date) == 8 { // yyyyMMdd → yyyy-MM-dd
				date = date[0:4] + "-" + date[4:6] + "-" + date[6:8]
			}
			loc, _, _ := sk.GetStringValue("InstallLocation")
			sizeKB, _, _ := sk.GetIntegerValue("EstimatedSize")
			size := ""
			if sizeKB > 0 {
				size = fmt.Sprintf("%.1f MB", float64(sizeKB)/1024)
			}
			susp := ""
			lower := strings.ToLower(name + " " + pub)
			for _, r := range ratKeywords {
				if strings.Contains(lower, r) {
					susp = "⚠ 远程控制工具"
					break
				}
			}
			progs = append(progs, prog{name + b.tag, ver, pub, date, loc, size, susp})
			sk.Close()
		}
		k.Close()
	}

	sort.Slice(progs, func(i, j int) bool {
		return strings.ToLower(progs[i].Name) < strings.ToLower(progs[j].Name)
	})

	out := make([][]string, 0, len(progs))
	for _, p := range progs {
		out = append(out, []string{p.Name, p.Version, p.Publisher, p.Date, p.Location, p.Size, p.Suspicious})
	}
	return out
}
