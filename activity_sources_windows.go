//go:build windows

// LNK 快捷方式 (Recent 文件夹) 解析
// Jump Lists (AutomaticDestinations) - 简化 OLE 扫描
// Recycle Bin $I 文件 - 二进制解析 (全盘)
// Scheduled Tasks - XML 解析 (递归)

package main

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fixedDrives 枚举所有固定逻辑盘 (GetLogicalDrives + GetDriveType FIXED)
func fixedDrives() []string {
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")
	getDriveType := kernel32.NewProc("GetDriveTypeW")
	r, _, _ := getLogicalDrives.Call()
	bits := uint32(r)
	var drives []string
	for i := 0; i < 26; i++ {
		if bits&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A' + i)) + `:\`
		p, _ := windows.UTF16PtrFromString(letter)
		dt, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(p)))
		if dt == 3 { // DRIVE_FIXED
			drives = append(drives, letter)
		}
	}
	return drives
}


// readLNKs 扫描 %APPDATA%\Microsoft\Windows\Recent\*.lnk
// 原生 MS-SHLLINK 解析 (无 PowerShell fork), 含目标三时间戳 + 卷序列号
func readLNKs() []ActivityItem {
	var out []ActivityItem
	appdata := osGetenv("APPDATA")
	if appdata == "" {
		return out
	}
	recentDir := filepath.Join(appdata, "Microsoft", "Windows", "Recent")
	entries, err := os.ReadDir(recentDir)
	if err != nil {
		return out
	}
	count := 0
	for _, e := range entries {
		if count >= 300 {
			break
		}
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".lnk") {
			continue
		}
		lnkPath := filepath.Join(recentDir, e.Name())
		data, err := os.ReadFile(lnkPath)
		if err != nil {
			continue
		}
		p := parseLNKBytes(data)
		if p == nil {
			continue
		}
		fi, _ := e.Info()
		var modTime time.Time
		if fi != nil {
			modTime = fi.ModTime()
		}
		target := p.TargetPath
		if target == "" {
			target = e.Name()[:len(e.Name())-4] // 去 .lnk
		}
		if p.Arguments != "" {
			target = target + " " + p.Arguments
		}
		// 取证细节: 目标三时间戳 + 大小 + 卷序列号
		detail := "→ " + target
		if p.WorkingDir != "" {
			detail += " | 工作目录: " + p.WorkingDir
		}
		if !p.WriteTime.IsZero() {
			detail += fmt.Sprintf(" | 目标时间: 建%s/改%s",
				p.CreateTime.Local().Format("01-02 15:04"), p.WriteTime.Local().Format("01-02 15:04"))
		}
		if p.VolumeSN != 0 {
			detail += fmt.Sprintf(" | 卷SN: %08X", p.VolumeSN)
		}
		if p.FileSize > 0 {
			detail += fmt.Sprintf(" | %d B", p.FileSize)
		}
		out = append(out, ActivityItem{
			Time: modTime,
			Type: "LNK",
			Event: "快捷方式: " + e.Name(),
			Detail: detail,
		})
		count++
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}


// readJumpLists 扫描 %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms
func readJumpLists() []ActivityItem {
	var out []ActivityItem
	appdata := osGetenv("APPDATA")
	if appdata == "" {
		return out
	}
	jlDir := filepath.Join(appdata, "Microsoft", "Windows", "Recent", "AutomaticDestinations")
	entries, err := os.ReadDir(jlDir)
	if err != nil {
		return out
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".automaticDestinations-ms") {
			continue
		}
		full := filepath.Join(jlDir, e.Name())
		fi, _ := e.Info()
		var modTime time.Time
		if fi != nil {
			modTime = fi.ModTime()
		}
		// App ID = 文件名前缀 (8 位 hex)
		appID := strings.TrimSuffix(e.Name(), ".automaticDestinations-ms")
		// 尝试 OLE 解析 (失败则只列元数据)
		files := parseJumpList(full)
		if len(files) > 0 {
			for i, f := range files {
				if i >= 20 {
					break
				}
				out = append(out, ActivityItem{
					Time: modTime,
					Type: "JumpList",
					Event: fmt.Sprintf("[%s] 最近文件: %s", appID, f.Name),
					Detail: f.Path,
				})
			}
		} else {
			out = append(out, ActivityItem{
				Time: modTime,
				Type: "JumpList",
				Event: fmt.Sprintf("AppID %s (OLE 解析失败, 列出文件名)", appID),
				Detail: full,
			})
		}
		count++
	}
	return out
}

type jlFile struct {
	Name string
	Path string
}

// parseJumpList 简单 OLE 解析 Jump List
// Jump List 是 OLE compound document, 含 DestList stream
// 这里用 ole 库或简化: 直接读文件, 找 Unicode 路径
func parseJumpList(path string) []jlFile {
	// 读 OLE 文件头检查 magic
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 8 {
		return nil
	}
	// OLE2 magic: D0 CF 11 E0 A1 B1 1A E1
	if !(data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0) {
		return nil
	}
	// 简化的 OLE 解析: 找 UTF-16LE 编码的盘符路径 (C:\...)
	var files []jlFile
	seen := map[string]bool{}
	for i := 0; i < len(data)-10; i += 2 {
		// 检查是否像 "X:\"
		if data[i+1] == 0 && data[i] >= 'A' && data[i] <= 'Z' &&
			data[i+2] == ':' && data[i+3] == 0 && data[i+4] == '\\' && data[i+5] == 0 {
			// 提取 UTF-16LE 字符串
			end := i
			for end < len(data)-2 {
				if data[end] == 0 && data[end+1] == 0 && data[end+2] == 0 && data[end+3] == 0 {
					break
				}
				end += 2
			}
			if end > i+6 {
				u16 := make([]uint16, 0, (end-i)/2)
				for k := i; k < end; k += 2 {
					u16 = append(u16, uint16(data[k])|uint16(data[k+1])<<8)
				}
				path := string(utf16.Decode(u16))
				if !seen[path] && len(path) > 5 {
					seen[path] = true
					files = append(files, jlFile{
						Name: filepath.Base(path),
						Path: path,
					})
				}
				i = end
			}
		}
	}
	return files
}

// readRecycleBin 扫描所有固定盘的 $Recycle.Bin\<SID>\$I*
func readRecycleBin() []ActivityItem {
	var out []ActivityItem
	count := 0
	for _, drive := range fixedDrives() {
		recycleRoot := drive + `\$Recycle.Bin`
		entries, err := os.ReadDir(recycleRoot)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			sidDir := filepath.Join(recycleRoot, e.Name())
			files, err := os.ReadDir(sidDir)
			if err != nil {
				continue
			}
			for _, f := range files {
				if count >= 500 {
					sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
					return out
				}
				if !strings.HasPrefix(f.Name(), "$I") {
					continue
				}
				info := parseRecycleBinI(filepath.Join(sidDir, f.Name()), drive)
				if info == nil {
					continue
				}
				out = append(out, *info)
				count++
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// $I 文件格式:
//
//	v2 (Vista+ / Win7+): 0-7 头(version=2) | 8-15 原始大小 | 16-23 删除时间
//	                     FILETIME | 24-31 流大小 | 32+ 原路径 UTF-16LE
//	v1 (Vista):          0-7 头(version=1) | 8-15 原始大小 | 16-23 删除时间
//	                     FILETIME | 24+ 原路径 UTF-16LE
func parseRecycleBinI(path string, drive string) *ActivityItem {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 32 {
		return nil
	}
	version := binary.LittleEndian.Uint64(data[0:8])
	if version != 1 && version != 2 {
		return nil // 非法 $I 文件
	}
	origSize := binary.LittleEndian.Uint64(data[8:16])
	ft := binary.LittleEndian.Uint64(data[16:24])
	t := fileTimeToTime(ft)
	pathStart := 24
	if version == 2 {
		pathStart = 32
	}
	if pathStart >= len(data) {
		return nil
	}
	u16 := make([]uint16, 0, (len(data)-pathStart)/2)
	for i := pathStart; i+1 < len(data); i += 2 {
		c := uint16(data[i]) | uint16(data[i+1])<<8
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	origPath := string(utf16.Decode(u16))
	if origPath == "" {
		return nil
	}
	return &ActivityItem{
		Time: t,
		Type: "回收站",
		Event: "已删除: " + filepath.Base(origPath),
		Detail: fmt.Sprintf("原路径: %s | 大小: %d 字节 | 盘: %s | 格式: v%d", origPath, origSize, drive, version),
	}
}

// readScheduledTasks 扫描 C:\Windows\System32\Tasks\*.xml
type taskXML struct {
	XMLName     xml.Name `xml:"Task"`
	RegistrationInfo struct {
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
		Date        string `xml:"Date"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		CalendarTrigger *struct {
			StartBoundary string `xml:"StartBoundary"`
		} `xml:"CalendarTrigger"`
		LogonTrigger   *struct{} `xml:"LogonTrigger"`
		BootTrigger    *struct{} `xml:"BootTrigger"`
	} `xml:"Triggers"`
	Actions struct {
		Exec struct {
			Command string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
	Settings struct {
		Enabled string `xml:"Enabled"`
	} `xml:"Settings"`
}

func readScheduledTasks() []ActivityItem {
	var out []ActivityItem
	root := `C:\Windows\System32\Tasks`
	type taskRow struct {
		rel  string
		mod  time.Time
		data []byte
	}
	var tasks []taskRow
	// 递归遍历: 任务几乎都在子目录 (\Microsoft\...) 里, 顶层只有零星几个
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 无权限子目录跳过
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".xml") {
			return nil
		}
		if len(tasks) >= 800 {
			return fs.SkipAll
		}
		fi, _ := d.Info()
		var mod time.Time
		if fi != nil {
			mod = fi.ModTime()
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		tasks = append(tasks, taskRow{rel, mod, data})
		return nil
	})
	for _, tk := range tasks {
		var t taskXML
		if err := xml.Unmarshal(tk.data, &t); err != nil {
			continue
		}
		enabled := t.Settings.Enabled
		if enabled == "" {
			enabled = "true"
		}
		trigger := ""
		if t.Triggers.CalendarTrigger != nil {
			trigger = "定时: " + t.Triggers.CalendarTrigger.StartBoundary
		} else if t.Triggers.LogonTrigger != nil {
			trigger = "登录时"
		} else if t.Triggers.BootTrigger != nil {
			trigger = "启动时"
		}
		name := strings.TrimSuffix(tk.rel, filepath.Ext(tk.rel))
		detail := fmt.Sprintf("执行: %s %s | 作者: %s | 启用: %s",
			t.Actions.Exec.Command, t.Actions.Exec.Arguments, t.RegistrationInfo.Author, enabled)
		if trigger != "" {
			detail += " | 触发: " + trigger
		}
		out = append(out, ActivityItem{
			Time: tk.mod,
			Type: "计划任务",
			Event: "任务: " + name,
			Detail: detail,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// 抑制未用警告
