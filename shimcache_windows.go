//go:build windows

// Shimcache (AppCompatCache) 解析
// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
// Win10 x64 布局: [u32 magic][u32 count] + 变长条目
//   { u64 unknown | u16 pathlen(chars) | path UTF16 | 补齐8 | u64 lastmod FT | u64 lastupdate }

package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"
)

type shimEntry struct {
	Path     string
	LastMod  time.Time // 条目内 FILETIME (近似: 常为 0 或未知纪元)
	HasTime  bool
}

// parseShimcacheWin10 解析 Win10 x64 AppCompatCache 数据块
func parseShimcacheWin10(data []byte) ([]shimEntry, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("数据过短")
	}
	count := int(binary.LittleEndian.Uint32(data[4:8]))
	if count <= 0 || count > 20000 {
		return nil, fmt.Errorf("非法条目数 %d", count)
	}
	var out []shimEntry
	off := 8 // Win10: magic(4) + count(4)
	for i := 0; i < count && off+18 <= len(data); i++ {
		entryStart := off
		_ = binary.LittleEndian.Uint64(data[off : off+8]) // unknown
		off += 8
		plen := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		if plen <= 0 || plen > 520 || off+plen*2 > len(data) {
			break
		}
		u := make([]uint16, plen)
		for k := 0; k < plen; k++ {
			u[k] = binary.LittleEndian.Uint16(data[off+k*2 : off+k*2+2])
		}
		path := string(utf16.Decode(u))
		off += plen * 2
		// 补齐到 8 字节对齐 (相对条目起始)
		pad := (8 - ((off - entryStart) % 8)) % 8
		off += pad
		if off+16 > len(data) {
			out = append(out, shimEntry{Path: path})
			break
		}
		lastMod := fileTimeToTime(binary.LittleEndian.Uint64(data[off : off+8]))
		off += 16 // lastmod + lastupdate
		hasT := !lastMod.IsZero() && lastMod.Year() > 2000 && lastMod.Year() < 2100
		out = append(out, shimEntry{Path: path, LastMod: lastMod.Local(), HasTime: hasT})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无有效条目")
	}
	return out, nil
}

func readShimcache() []ActivityItem {
	var out []ActivityItem
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`, registry.READ)
	if err != nil {
		return []ActivityItem{{
			Type:   "Shimcache",
			Event:  "AppCompatCache 不可读",
			Detail: err.Error(),
		}}
	}
	defer k.Close()
	data, _, err := k.GetBinaryValue("AppCompatCache")
	if err != nil {
		return []ActivityItem{{
			Type: "Shimcache", Event: "AppCompatCache 值读取失败", Detail: err.Error(),
		}}
	}
	entries, perr := parseShimcacheWin10(data)
	if perr != nil {
		return []ActivityItem{{
			Type: "Shimcache", Event: "解析失败 (可能非 Win10 x64 布局)",
			Detail: perr.Error(),
		}}
	}
	for i, e := range entries {
		if i >= 1000 { // 上限
			break
		}
		if e.Path == "" {
			continue
		}
		item := ActivityItem{
			Type:   "Shimcache",
			Event:  "执行痕迹: " + baseName(e.Path),
			Detail: "路径: " + e.Path + " | 时间=条目修改时间(参考)",
		}
		if e.HasTime {
			item.Time = e.LastMod
			item.Approx = true
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Time.IsZero() {
			return false
		}
		if out[j].Time.IsZero() {
			return true
		}
		return out[i].Time.After(out[j].Time)
	})
	return out
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
