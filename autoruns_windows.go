//go:build windows

// 自启动项枚举 (对标 Sysinternals Autoruns 核心子集)
// 覆盖: Run/RunOnce(8处) + Winlogon劫持点 + AppInit_DLLs + IFEO Debugger
//       + Active Setup + BootExecute + 服务/驱动(含 svchost ServiceDll) + 启动文件夹(2处)
// 状态列: 读取 StartupApproved 注册表区分 启用/已禁用
// 可疑启发式: 用户可写目录(Temp/Public/PerfLogs/Downloads) + 脚本扩展

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type autoRunRow struct {
	Location   string
	Name       string
	State      string // "启用" / "已禁用" / ""
	Command    string
	Suspicious string // "" 或 "⚠ 原因"
}

// startupApproval 查询 StartupApproved 二进制标志
// 路径: <root>\...\Explorer\StartupApproved\{Run|StartupFolder}\<name>
// 布局: u32 标志 + 8 字节 FILETIME; 偶数(0x02/0x06)=启用, 奇数(0x03/0x0b)=禁用
func startupApproval(root registry.Key, sub, name string) string {
	k, err := registry.OpenKey(root,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\`+sub, registry.READ)
	if err != nil {
		return ""
	}
	defer k.Close()
	data, _, err := k.GetBinaryValue(name)
	if err != nil || len(data) < 4 {
		return ""
	}
	flag := binary.LittleEndian.Uint32(data[0:4])
	if flag == 0 {
		return ""
	}
	if flag&1 == 1 {
		return "已禁用"
	}
	return "启用"
}

func readAutoRuns() [][]string {
	var rows []autoRunRow
	add := func(loc, name, cmd string) {
		if strings.TrimSpace(name) == "" && strings.TrimSpace(cmd) == "" {
			return
		}
		rows = append(rows, autoRunRow{Location: loc, Name: name, Command: cmd,
			Suspicious: checkAutoRunSuspicious(cmd)})
	}

	// 1) Run / RunOnce (8 个位置, 附带 StartupApproved 状态)
	runKeys := []struct {
		root registry.Key
		path string
		loc  string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run (32位)"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce (32位)"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "HKLM 策略 Run"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKCU Run"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU RunOnce"},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "HKCU 策略 Run"},
	}
	for _, rk := range runKeys {
		k, err := registry.OpenKey(rk.root, rk.path, registry.READ)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(200)
		for _, n := range names {
			if v, _, err := k.GetStringValue(n); err == nil {
				state := startupApproval(rk.root, "Run", n)
				// WOW6432Node 的状态也存在主 StartupApproved\Run 下, 上面已覆盖
				rows = append(rows, autoRunRow{Location: rk.loc, Name: n, State: state,
					Command: v, Suspicious: checkAutoRunSuspicious(v)})
			}
		}
		k.Close()
	}

	// 2) Winlogon Userinit / Shell (经典劫持点)
	wl, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.READ)
	if err == nil {
		if v, _, e := wl.GetStringValue("Userinit"); e == nil {
			susp := ""
			if v != `C:\Windows\system32\userinit.exe,` {
				susp = "⚠ Userinit 非默认值 (劫持点)"
			}
			rows = append(rows, autoRunRow{Location: "Winlogon", Name: "Userinit", Command: v, Suspicious: susp})
		}
		if v, _, e := wl.GetStringValue("Shell"); e == nil {
			susp := ""
			if !strings.HasPrefix(strings.ToLower(v), "explorer.exe") {
				susp = "⚠ Shell 非默认值 (劫持点)"
			}
			rows = append(rows, autoRunRow{Location: "Winlogon", Name: "Shell", Command: v, Suspicious: susp})
		}
		wl.Close()
	}

	// 3) AppInit_DLLs (全局 DLL 注入)
	wn, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, registry.READ)
	if err == nil {
		if v, _, e := wn.GetStringValue("AppInit_DLLs"); e == nil && strings.TrimSpace(v) != "" {
			rows = append(rows, autoRunRow{Location: "AppInit_DLLs", Name: "AppInit_DLLs", Command: v,
				Suspicious: "⚠ 全局 DLL 注入点 (AppInit_DLLs 非空)"})
		}
		wn.Close()
	}

	// 4) IFEO Debugger (映像劫持)
	ifeo, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, registry.READ)
	if err == nil {
		subs, _ := ifeo.ReadSubKeyNames(500)
		for _, s := range subs {
			sk, err := registry.OpenKey(ifeo, s, registry.READ)
			if err != nil {
				continue
			}
			if dbg, _, e := sk.GetStringValue("Debugger"); e == nil && dbg != "" {
				rows = append(rows, autoRunRow{Location: "IFEO", Name: s, Command: dbg,
					Suspicious: "⚠ IFEO Debugger (映像劫持/持久化)"})
			}
			sk.Close()
		}
		ifeo.Close()
	}

	// 5) Active Setup StubPath
	as, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Active Setup\Installed Components`, registry.READ)
	if err == nil {
		subs, _ := as.ReadSubKeyNames(300)
		for _, s := range subs {
			sk, err := registry.OpenKey(as, s, registry.READ)
			if err != nil {
				continue
			}
			if sp, _, e := sk.GetStringValue("StubPath"); e == nil && sp != "" {
				add("Active Setup", s, sp)
			}
			sk.Close()
		}
		as.Close()
	}

	// 6) BootExecute (会话管理器启动执行)
	sm, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager`, registry.READ)
	if err == nil {
		if v, _, e := sm.GetStringsValue("BootExecute"); e == nil {
			joined := strings.Join(v, "; ")
			susp := ""
			if joined != "autocheck autochk *" {
				susp = "⚠ BootExecute 非默认值"
			}
			rows = append(rows, autoRunRow{Location: "BootExecute", Name: "BootExecute", Command: joined, Suspicious: susp})
		}
		sm.Close()
	}

	// 7) 服务 + 驱动 (非禁用, svchost 补读 ServiceDll 载荷)
	svc, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.READ)
	if err == nil {
		subs, _ := svc.ReadSubKeyNames(1500)
		for _, s := range subs {
			sk, err := registry.OpenKey(svc, s, registry.READ)
			if err != nil {
				continue
			}
			img, _, e1 := sk.GetStringValue("ImagePath")
			if e1 != nil || img == "" {
				sk.Close()
				continue
			}
			start, _, _ := sk.GetIntegerValue("Start")
			if start == 4 { // 禁用的跳过
				sk.Close()
				continue
			}
			typ, _, _ := sk.GetIntegerValue("Type")
			loc := "服务"
			if typ == 1 {
				loc = "驱动"
			}
			// svchost 服务的真实载荷在 Parameters\ServiceDll
			cmd := img
			susp := checkAutoRunSuspicious(img)
			if strings.Contains(strings.ToLower(img), "svchost") && loc == "服务" {
				if pk, perr := registry.OpenKey(sk, "Parameters", registry.READ); perr == nil {
					if dll, _, derr := pk.GetStringValue("ServiceDll"); derr == nil && dll != "" {
						cmd = img + "  → DLL: " + dll
						if s2 := checkAutoRunSuspicious(dll); s2 != "" {
							susp = s2
						}
					}
					pk.Close()
				}
			}
			startLabel := map[uint64]string{0: "Boot", 1: "System", 2: "自动", 3: "手动"}[start]
			rows = append(rows, autoRunRow{Location: loc,
				Name:    fmt.Sprintf("%s [%s]", s, startLabel),
				Command: cmd, Suspicious: susp})
			sk.Close()
		}
		svc.Close()
	}

	// 8) 启动文件夹 (所有用户 + 当前用户, 附带 StartupApproved 状态)
	startupDirs := []struct{ dir, loc string }{
		{os.Getenv("ProgramData") + `\Microsoft\Windows\Start Menu\Programs\Startup`, "启动文件夹 (所有用户)"},
		{os.Getenv("APPDATA") + `\Microsoft\Windows\Start Menu\Programs\Startup`, "启动文件夹 (当前用户)"},
	}
	for _, d := range startupDirs {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			// 状态在 StartupApproved\StartupFolder\<文件名>
			state := startupApproval(registry.CURRENT_USER, "StartupFolder", e.Name())
			if state == "" {
				state = startupApproval(registry.LOCAL_MACHINE, "StartupFolder", e.Name())
			}
			rows = append(rows, autoRunRow{Location: d.loc, Name: e.Name(), State: state,
				Command: filepath.Join(d.dir, e.Name()),
				Suspicious: checkAutoRunSuspicious(filepath.Join(d.dir, e.Name()))})
		}
	}

	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, []string{r.Location, r.Name, r.State, r.Command, r.Suspicious})
	}
	return out
}

// checkAutoRunSuspicious 启发式可疑检测
//   - 用户可写目录: Temp / Public / PerfLogs / Downloads (恶意软件常驻点)
//   - 脚本扩展: 命令中任一 token 以 .vbs/.js/.ps1/.bat/.scr 等结尾
func checkAutoRunSuspicious(cmd string) string {
	l := strings.ToLower(cmd)
	var reasons []string
	for _, pat := range []string{`\temp\`, `\appdata\local\temp\`, `\users\public\`, `c:\perflogs\`, `\downloads\`, `\windows\fonts\`} {
		if strings.Contains(l, pat) {
			reasons = append(reasons, "用户可写目录")
			break
		}
	}
	scriptExts := map[string]bool{
		".vbs": true, ".js": true, ".jse": true, ".wsf": true, ".wsh": true,
		".ps1": true, ".bat": true, ".cmd": true, ".scr": true, ".hta": true, ".jar": true,
	}
	for _, tok := range strings.Fields(cmd) {
		t := strings.Trim(strings.TrimSpace(tok), `"`)
		dot := strings.LastIndex(t, ".")
		if dot >= 0 && scriptExts[strings.ToLower(t[dot:])] {
			reasons = append(reasons, "脚本启动")
			break
		}
	}
	if len(reasons) > 0 {
		return "⚠ " + strings.Join(reasons, "+")
	}
	return ""
}

// firstTokenOf 取命令的第一个 token (可执行文件路径)
func firstTokenOf(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 0 && s[0] == '"' {
		if i := strings.Index(s[1:], `"`); i >= 0 {
			return s[1 : i+1]
		}
	}
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}
