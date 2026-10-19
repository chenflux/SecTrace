//go:build windows

// Amcache.hve 加载与读取
// RegLoadKey 需 SeRestorePrivilege → AdjustTokenPrivileges 提权 →
// 挂载为 HKLM\SecTrace$Amcache → 读 root\InventoryApplicationFile →
// 用完 RegUnLoadKey (不留痕)
//
// 字段: LowerCaseLongPath / Name / Publisher / Version / LinkDate
// 时间 = 键 LastWriteTime ≈ 首次执行时间 (≈ 标记)

package main

import (
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const amcacheMount = `SecTrace$Amcache`

// enablePrivilege 提权指定权限 (SeRestorePrivilege/SeBackupPrivilege)
func enablePrivilege(name string) bool {
	adv := windows.NewLazySystemDLL("advapi32.dll")
	openProcToken := adv.NewProc("OpenProcessToken")
	lookupPriv := adv.NewProc("LookupPrivilegeValueW")
	adjustPriv := adv.NewProc("AdjustTokenPrivileges")
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getCurProc := k32.NewProc("GetCurrentProcess")

	type luid struct {
		LowPart  uint32
		HighPart int32
	}
	type tokenPriv struct {
		PrivilegeCount uint32
		Luid           luid
		Attributes     uint32
	}

	h, _, _ := getCurProc.Call()
	var token windows.Token
	r, _, _ := openProcToken.Call(h, 0x28, uintptr(unsafe.Pointer(&token))) // TOKEN_ADJUST_PRIVILEGES|QUERY
	if r == 0 {
		return false
	}
	defer token.Close()

	pn, _ := windows.UTF16PtrFromString(name)
	var l luid
	r2, _, _ := lookupPriv.Call(0, uintptr(unsafe.Pointer(pn)), uintptr(unsafe.Pointer(&l)))
	if r2 == 0 {
		return false
	}
	tp := tokenPriv{PrivilegeCount: 1, Luid: l, Attributes: 3} // SE_PRIVILEGE_ENABLED
	r3, _, _ := adjustPriv.Call(uintptr(token), uintptr(unsafe.Pointer(&tp)), 0, 0, 0, 0)
	return r3 != 0
}

func readAmcache() []ActivityItem {
	var out []ActivityItem
	hivePath := `C:\Windows\appcompat\Programs\Amcache.hve`

	adv := windows.NewLazySystemDLL("advapi32.dll")
	regLoad := adv.NewProc("RegLoadKeyW")
	regUnload := adv.NewProc("RegUnLoadKeyW")

	enablePrivilege("SeRestorePrivilege")
	enablePrivilege("SeBackupPrivilege")

	pSub, _ := windows.UTF16PtrFromString(amcacheMount)
	pFile, _ := windows.UTF16PtrFromString(hivePath)
	r, _, errno := regLoad.Call(uintptr(registry.LOCAL_MACHINE),
		uintptr(unsafe.Pointer(pSub)), uintptr(unsafe.Pointer(pFile)))
	if r != 0 {
		return []ActivityItem{{
			Type:   "Amcache",
			Event:  "Amcache.hve 挂载失败",
			Detail: fmt.Sprintf("RegLoadKey: %v (需管理员; 文件: %s)", errno, hivePath),
		}}
	}
	defer regUnload.Call(uintptr(registry.LOCAL_MACHINE), uintptr(unsafe.Pointer(pSub)))

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		amcachePath("InventoryApplicationFile"), registry.READ)
	if err != nil {
		// 旧版路径 (Win8/早期Win10)
		k, err = registry.OpenKey(registry.LOCAL_MACHINE,
			amcachePath("File"), registry.READ)
		if err != nil {
			return []ActivityItem{{
				Type: "Amcache", Event: "InventoryApplicationFile 键不存在",
				Detail: "hve 已挂载但结构未知: " + err.Error(),
			}}
		}
	}
	defer k.Close()

	subs, _ := k.ReadSubKeyNames(4000)
	for i, s := range subs {
		if i >= 1000 {
			break
		}
		sk, err := registry.OpenKey(k, s, registry.READ)
		if err != nil {
			continue
		}
		path, _, _ := sk.GetStringValue("LowerCaseLongPath")
		name, _, _ := sk.GetStringValue("Name")
		pub, _, _ := sk.GetStringValue("Publisher")
		ver, _, _ := sk.GetStringValue("Version")
		link, _, _ := sk.GetStringValue("LinkDate")

		if path == "" && name == "" {
			sk.Close()
			continue
		}
		display := name
		if display == "" {
			display = baseName(path)
		}
		detail := fmt.Sprintf("路径: %s | 发布者: %s | 版本: %s | 链接日期: %s | 时间=键最后写入(≈首次执行)",
			path, pub, ver, link)
		item := ActivityItem{
			Approx: true,
			Type:   "Amcache",
			Event:  "程序清单: " + display,
			Detail: detail,
		}
		if stat, serr := sk.Stat(); serr == nil {
			item.Time = stat.ModTime()
		}
		sk.Close()
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

func amcachePath(sub string) string {
	return amcacheMount + `\root\` + sub
}
