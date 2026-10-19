//go:build windows

// Prefetch (SCCA) 深度解析:
// Win10+ 的 .pf 为 XPRESS-Huffman 压缩 (MAM 头), 解压后为 SCCA 结构
// 经典布局 (v23/26/30): 0xC8 起 8 个最后运行 FILETIME, 随后运行次数
// Win11 24H2 (v31) 变更了布局且未公开文档 → 优雅回退到文件 mtime

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// prefetchDetail 解析单个 .pf (解压 + SCCA)
// 返回: 运行次数, 最后 N 次运行时间 (时间倒序), 失败原因
type prefetchInfo struct {
	RunCount int
	RunTimes []time.Time // 倒序
	Note     string
}

func parsePrefetchFile(path string, fi os.FileInfo) prefetchInfo {
	var info prefetchInfo
	data, err := os.ReadFile(path)
	if err != nil {
		info.Note = err.Error()
		return info
	}
	if len(data) > 12 && data[0] == 'M' && data[1] == 'A' && data[2] == 'M' {
		usize := binary.LittleEndian.Uint32(data[4:8])
		dec, err := xpressHuffmanDecompress(data[8:], int(usize)+64)
		if err != nil && len(dec) == 0 {
			info.Note = "解压失败: " + err.Error()
			return info
		}
		// 解压器输出可能 ≥ usize (尾部填充位解码的垃圾), 按 usize 截断
		if int(usize) <= len(dec) {
			dec = dec[:usize]
		}
		return parseSCCA(dec, fi)
	}
	// 未压缩 (Vista-Win8): SCCA 直接在文件头
	return parseSCCA(data, fi)
}

// parseSCCA 解析 SCCA 结构 (兼容 [4B 前缀][SCCA] 包装)
func parseSCCA(dec []byte, fi os.FileInfo) prefetchInfo {
	var info prefetchInfo
	s := dec
	// Win11 包装: [u32 版本][SCCA...]
	if len(s) > 8 && s[4] == 'S' && s[5] == 'C' && s[6] == 'C' && s[7] == 'A' {
		info.Note = fmt.Sprintf("Win11 包装 (前缀=0x%X)", binary.LittleEndian.Uint32(s[0:4]))
		s = s[4:]
	} else if !(len(s) > 4 && s[0] == 'S' && s[1] == 'C' && s[2] == 'C' && s[3] == 'A') {
		info.Note = "非 SCCA 签名"
		return info
	}
	version := s[3] // 'A'=0x41; 真实版本号在 sig 后? 保守: 用已知布局判断
	_ = version

	// 经典布局: 0xC8 起 8 个 FILETIME (v23 只取第 1 个, v26/30 全 8 个)
	if len(s) < 0x114 {
		info.Note = "SCCA 过短"
		return info
	}
	var times []time.Time
	for i := 0; i < 8; i++ {
		ft := binary.LittleEndian.Uint64(s[0xC8+i*8 : 0xD0+i*8])
		t := fileTimeToTime(ft)
		if t.IsZero() || t.Year() < 2000 || t.Year() > 2100 {
			continue
		}
		times = append(times, t.Local())
	}
	if len(times) == 0 {
		info.Note = "无有效运行时间 (Win11 24H2 v31 布局变更, 回退 mtime)"
		return info
	}
	sort.Slice(times, func(a, b int) bool { return times[a].After(times[b]) })
	// 运次数候选位置 (不同版本 0x110/0x114/0x118)
	count := 0
	for _, off := range []int{0x110, 0x114, 0x118} {
		v := int(binary.LittleEndian.Uint32(s[off : off+4]))
		if v > 0 && v < 10000000 && v >= len(times) {
			count = v
			break
		}
	}
	info.RunTimes = times
	info.RunCount = count
	return info
}

// readPrefetchDeep 深度 Prefetch 收集 (内嵌运行时间 + 次数)
func readPrefetchDeep() []ActivityItem {
	var out []ActivityItem
	dir := `C:\Windows\Prefetch`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []ActivityItem{{
			Type:   "程序运行",
			Event:  "无法读取 Prefetch (需管理员)",
			Detail: err.Error(),
		}}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := prefetchPattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		full := filepath.Join(dir, e.Name())
		fi, err := e.Info()
		if err != nil {
			continue
		}
		name := CleanText(strings.ReplaceAll(strings.ReplaceAll(m[1], "~", ""), "_", " "))
		info := parsePrefetchFile(full, fi)

		// 主时间 = 最新运行时间 (精确); 无则 mtime (近似)
		item := ActivityItem{Type: "程序运行"}
		if len(info.RunTimes) > 0 {
			item.Time = info.RunTimes[0]
			ev := fmt.Sprintf("执行程序: %s", name)
			if info.RunCount > 0 {
				ev += fmt.Sprintf(" (%d 次)", info.RunCount)
			}
			item.Event = ev
			var ts []string
			for _, t := range info.RunTimes {
				ts = append(ts, t.Format("01-02 15:04:05"))
			}
			detail := "运行时间: " + strings.Join(ts, " | ")
			if info.Note != "" {
				detail += " | " + info.Note
			}
			item.Detail = detail
		} else {
			item.Time = fi.ModTime()
			item.Approx = true
			item.Event = fmt.Sprintf("执行程序: %s", name)
			note := info.Note
			if note == "" {
				note = "时间=文件修改时间(近似)"
			}
			item.Detail = note
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}
