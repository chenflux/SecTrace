//go:build windows

// 用户登录/登出记录
// 来源:
//   - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
//     每个 SID 子键: ProfileImagePath, RefCount, 等; 键 LastWriteTime ≈ 上次交互时间
//   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
//     LastLoggedOnUser, LastLoggedOnSAMUser
//   - HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\<br>
//     RDP 远程登录信息
//
// 注: 完整登录/登出历史需要事件日志 4624/4625/4634/4647/4648,
// 但用户禁用事件日志, 这里只给 "当前登录" + "所有用户配置".

package main

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// readUserSessions 读所有用户配置 + 当前登录信息
func readUserSessions() []ActivityItem {
	var out []ActivityItem

	// 1) ProfileList\<SID> - 所有曾经登录过的用户
	pl, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.READ)
	if err == nil {
		sids, _ := pl.ReadSubKeyNames(50)
		for _, sid := range sids {
			// 跳过非 SID 形式的 (如 S-1-5-21-...)
			if !strings.HasPrefix(sid, "S-1-") {
				continue
			}
			pk, err := registry.OpenKey(pl, sid, registry.READ)
			if err != nil {
				continue
			}
			profilePath, _, _ := pk.GetStringValue("ProfileImagePath")
			refCount, _, _ := pk.GetIntegerValue("RefCount")
			localLoad, _, _ := pk.GetIntegerValue("LocalProfileLoaded")
			state, _, _ := pk.GetIntegerValue("State")
			// 0=正常, 1=备份中, 2=预删除

			// 键 LastWriteTime ≈ 该用户最近一次登录/操作时间
			stat, _ := pk.Stat()
			var modTime time.Time
			if stat != nil {
				modTime = stat.ModTime()
			}

			userName := extractUserFromPath(profilePath)

			statusStr := "正常"
			if state == 1 {
				statusStr = "备份中"
			} else if state == 2 {
				statusStr = "预删除"
			}
			loadedStr := "未加载"
			if localLoad == 1 {
				loadedStr = "已加载"
			}

			detail := fmt.Sprintf("用户名: %s | 路径: %s | 状态: %s | 加载: %s | 引用: %d",
				userName, profilePath, statusStr, loadedStr, refCount)
			// 标记: 键 LastWriteTime = 该用户配置目录的最近活动时间
			out = append(out, ActivityItem{
				Time:   modTime,
				Approx: true, // 键 LastWriteTime 是近似时间
				Type:   "用户",
				Event:  fmt.Sprintf("用户配置: %s", userName),
				Detail: detail + " | 时间=配置键最后写入(近似)",
			})
			pk.Close()
		}
		pl.Close()
	}

	// 2) Authentication\LogonUI - 最后登录的用户
	// 注: LogonUI 注册表只存"最后登录用户/SAM账户"快照 (1 条),
	// 全量登录/登出历史请用 evl_rdp 场景加载 Security 事件日志 (4624/4625/4634/4647/4778/4779).
	// 这里不再追加 2 条重复条目.

	// 3) 当前用户信息 (HKCU\Volatile Environment)
	ve, err := registry.OpenKey(registry.CURRENT_USER, `Volatile Environment`, registry.READ)
	if err == nil {
		stat, _ := ve.Stat()
		var t time.Time
		if stat != nil {
			t = stat.ModTime()
		}
		if userName, _, err := ve.GetStringValue("USERNAME"); err == nil && userName != "" {
			out = append(out, ActivityItem{
				Time:   t,
				Approx: true,
				Type:   "用户",
				Event:  fmt.Sprintf("当前登录用户: %s", userName),
				Detail: "HKCU\\Volatile Environment\\USERNAME (当前用户上下文)",
			})
		}
		if logonServer, _, err := ve.GetStringValue("LOGONSERVER"); err == nil && logonServer != "" {
			out = append(out, ActivityItem{
				Time:   t,
				Approx: true,
				Type:   "用户",
				Event:  fmt.Sprintf("登录服务器: %s", logonServer),
				Detail: "HKCU\\Volatile Environment\\LOGONSERVER (域登录服务器)",
			})
		}
		ve.Close()
	}

	return out
}

// extractUserFromPath 从 C:\Users\xxx 提取用户名
func extractUserFromPath(p string) string {
	if p == "" {
		return "(未知)"
	}
	// 取最后一段
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
