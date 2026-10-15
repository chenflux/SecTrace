//go:build windows

// BAM (Background Activity Moderator) + UserAssist
// 程序执行证据, 即使 Prefetch 被清也能恢复

package main

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/windows/registry"
)

// readBAM 读 HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
// 值名 = exe 路径, 值数据前 8 字节 = 最后执行 FILETIME
func readBAM() []ActivityItem {
	var out []ActivityItem
	base := `SYSTEM\CurrentControlSet\Services\bam`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return out
	}
	defer root.Close()

	// \State\UserSettings\<SID>
	state, err := registry.OpenKey(root, "State", registry.READ)
	if err != nil {
		return out
	}
	defer state.Close()

	userSettings, err := registry.OpenKey(state, "UserSettings", registry.READ)
	if err != nil {
		return out
	}
	defer userSettings.Close()

	sids, _ := userSettings.ReadSubKeyNames(20)
	for _, sid := range sids {
		k, err := registry.OpenKey(userSettings, sid, registry.READ)
		if err != nil {
			continue
		}
		values, _ := k.ReadValueNames(200)
		for _, name := range values {
			if name == "Version" || name == "UserCell" {
				continue
			}
			data, _, err := k.GetBinaryValue(name)
			if err != nil || len(data) < 8 {
				continue
			}
			ft := binary.LittleEndian.Uint64(data[0:8])
			t := fileTimeToTime(ft)
			out = append(out, ActivityItem{
				Time: t,
				Type: "BAM",
				Event: "后台执行: " + filepath.Base(name),
				Detail: "完整路径: " + name,
			})
		}
		k.Close()
	}
	return out
}

// readUserAssist 读 HKCU\...\Explorer\UserAssist
// 多个 GUID 子键, 值名经 ROT13 编码, 值数据 60 字节后是 FILETIME
func readUserAssist() []ActivityItem {
	var out []ActivityItem
	base := `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	root, err := registry.OpenKey(registry.CURRENT_USER, base, registry.READ)
	if err != nil {
		return out
	}
	defer root.Close()

	guids, _ := root.ReadSubKeyNames(20)
	for _, guid := range guids {
		k, err := registry.OpenKey(root, guid, registry.READ)
		if err != nil {
			continue
		}
		values, _ := k.ReadValueNames(500)
		for _, name := range values {
			// 值名是 ROT13 编码的程序路径
			decoded := rot13(name)
			data, _, err := k.GetBinaryValue(name)
			if err != nil {
				continue
			}
			// Win7 格式: 0-4 count, 60-68 FILETIME, 72+ path
			// Win10 格式: 0-4 count, 4-12 focus time, 12-16 focus count, 60-72 last run FILETIME
			var ft uint64
			if len(data) >= 72 {
				ft = binary.LittleEndian.Uint64(data[60:68])
			} else if len(data) >= 68 {
				ft = binary.LittleEndian.Uint64(data[60:68])
			} else if len(data) >= 16 {
				ft = binary.LittleEndian.Uint64(data[8:16])
			}
			if ft == 0 {
				continue
			}
			t := fileTimeToTime(ft)
			out = append(out, ActivityItem{
				Time: t,
				Type: "UserAssist",
				Event: "Explorer启动: " + filepath.Base(decoded),
				Detail: "完整路径: " + decoded,
			})
		}
		k.Close()
	}
	return out
}

func rot13(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'M', r >= 'a' && r <= 'm':
			b.WriteRune(r + 13)
		case r >= 'N' && r <= 'Z', r >= 'n' && r <= 'z':
			b.WriteRune(r - 13)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func fileTimeToTime(ft uint64) time.Time {
	const epochDiff uint64 = 116444736000000000
	if ft < epochDiff {
		return time.Time{}
	}
	us := int64((ft - epochDiff) / 10)
	return time.UnixMicro(us)
}

// 抑制未用警告
var _ = utf8.RuneCountInString
