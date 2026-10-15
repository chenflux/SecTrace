//go:build windows

// LNK 快捷方式 (Recent 文件夹) - 用 PowerShell COM 解析
// Jump Lists (AutomaticDestinations) - 列举文件 + 用 ole 解析
// Recycle Bin $I 文件 - 二进制解析
// Scheduled Tasks - XML 解析

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// LnkEntry 单个 LNK 文件的解析结果
type LnkEntry struct {
	Target       string
	WorkDir      string
	Arguments    string
	LnkModTime   time.Time
	TargetMTime  time.Time // 来自 TargetIDList 的时间戳 (如可解析)
}

// readLNKs 扫描 %APPDATA%\Microsoft\Windows\Recent\*.lnk
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
	// 限制最多 200 个
	count := 0
	for _, e := range entries {
		if count >= 200 {
			break
		}
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".lnk") {
			continue
		}
		lnkPath := filepath.Join(recentDir, e.Name())
		fi, _ := e.Info()
		var modTime time.Time
		if fi != nil {
			modTime = fi.ModTime()
		}
		// 解析 LNK (用 PowerShell COM)
		info := parseLnkViaPowerShell(lnkPath)
		if info == nil {
			continue
		}
		target := info.Target
		if target == "" {
			target = e.Name()[:len(e.Name())-4] // 去 .lnk
		}
		args := info.Arguments
		if args != "" {
			target = target + " " + args
		}
		out = append(out, ActivityItem{
			Time: modTime,
			Type: "LNK",
			Event: "快捷方式: " + e.Name(),
			Detail: "→ " + target + " | 工作目录: " + info.WorkDir,
		})
		count++
	}
	// 按时间排序
	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}

// parseLnkViaPowerShell 调用 powershell 解析 LNK
func parseLnkViaPowerShell(lnkPath string) *LnkEntry {
	if _, err := os.Stat(lnkPath); err != nil {
		return nil
	}
	// 转义路径中的单引号
	escaped := strings.ReplaceAll(lnkPath, "'", "''")
	psCmd := fmt.Sprintf(
		"$ErrorActionPreference='SilentlyContinue';"+
			"$s=New-Object -ComObject WScript.Shell;"+
			"$l=$s.CreateShortcut('%s');"+
			"Write-Output ([PSCustomObject]@{"+
			"Target=[string]$l.TargetPath;"+
			"WorkDir=[string]$l.WorkingDirectory;"+
			"Arguments=[string]$l.Arguments}|ConvertTo-Json -Compress)",
		escaped)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	// 简单解析 JSON
	s := strings.TrimSpace(string(out))
	if s == "" || s == "null" {
		return nil
	}
	// 简单解析
	info := &LnkEntry{}
	for _, line := range strings.Split(s, ",") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, `"Target":`):
			info.Target = strings.Trim(line[9:], `"`)
		case strings.HasPrefix(line, `"WorkDir":`):
			info.WorkDir = strings.Trim(line[10:], `"`)
		case strings.HasPrefix(line, `"Arguments":`):
			info.Arguments = strings.Trim(line[12:], `"`)
		}
	}
	// 简单 JSON 也可能没引号
	if info.Target == "" {
		// 尝试更宽松的解析
		if idx := strings.Index(s, `"Target":"`); idx >= 0 {
			rest := s[idx+10:]
			if end := strings.Index(rest, `"`); end > 0 {
				info.Target = rest[:end]
			}
		}
	}
	return info
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

// readRecycleBin 扫描 C:\$Recycle.Bin\<SID>\$I*
func readRecycleBin() []ActivityItem {
	var out []ActivityItem
	recycleRoot := `C:\$Recycle.Bin`
	entries, err := os.ReadDir(recycleRoot)
	if err != nil {
		return out
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sid := e.Name()
		sidDir := filepath.Join(recycleRoot, sid)
		files, err := os.ReadDir(sidDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if count >= 200 {
				break
			}
			if !strings.HasPrefix(f.Name(), "$I") {
				continue
			}
			info := parseRecycleBinI(filepath.Join(sidDir, f.Name()))
			if info == nil {
				continue
			}
			out = append(out, *info)
			count++
		}
	}
	// 按时间排序
	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}

// $I 文件格式 (Win 10):
// 0-7: 头 (version=2 in little-endian)
// 8-15: 原始文件大小
// 16-23: 删除时间 FILETIME
// 24-31: 原始文件大小 (重复, for streams)
// 32-?: 原路径 (UTF-16LE, null-terminated)
func parseRecycleBinI(path string) *ActivityItem {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 32 {
		return nil
	}
	// 校验 version (前 8 字节, 末位是 version)
	version := binary.LittleEndian.Uint32(data[0:4])
	if version == 0 || version > 10 {
		// 可能是 Win 8+ 格式
	}
	origSize := binary.LittleEndian.Uint64(data[8:16])
	ft := binary.LittleEndian.Uint64(data[16:24])
	t := fileTimeToTime(ft)
	// 路径 (offset 24 之后, UTF-16LE, null-terminated)
	pathStart := 24
	// Win10 在 24 之后还有 8 字节 (stream size), 然后 8 字节 padding, 然后 path
	if len(data) > 32 {
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
		Detail: fmt.Sprintf("原路径: %s | 大小: %d 字节", origPath, origSize),
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
	dir := `C:\Windows\System32\Tasks`
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	count := 0
	for _, e := range entries {
		if count >= 200 {
			break
		}
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".xml") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		var t taskXML
		if err := xml.Unmarshal(data, &t); err != nil {
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
		// 任务名 = 文件名 (去 .xml, 反斜杠替换为 \)
		name := strings.TrimSuffix(e.Name(), ".xml")
		// 注册表任务用反斜杠表示路径, 比如 \Microsoft\Windows\...
		// 替换为 /
		displayName := strings.ReplaceAll(name, `\`, "/")
		if displayName == "" {
			displayName = name
		}
		detail := fmt.Sprintf("执行: %s %s | 作者: %s | 启用: %s",
			t.Actions.Exec.Command, t.Actions.Exec.Arguments, t.RegistrationInfo.Author, enabled)
		if trigger != "" {
			detail += " | 触发: " + trigger
		}
		// 时间用文件修改时间
		fi, _ := e.Info()
		var modTime time.Time
		if fi != nil {
			modTime = fi.ModTime()
		}
		out = append(out, ActivityItem{
			Time: modTime,
			Type: "计划任务",
			Event: "任务: " + displayName,
			Detail: detail,
		})
		count++
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}

// 抑制未用警告
var _ = bytes.NewBuffer
