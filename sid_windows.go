//go:build windows

// SID → 账户名翻译 (带缓存)
// 用于事件详情中的 S-1-5-21-... → DOMAIN\user 可读化

package main

import (
	"regexp"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var sidVar = struct {
	mu    sync.Mutex
	cache map[string]string
}{cache: map[string]string{}}

// 常见 SID 静态表 (免 API 调用)
var wellKnownSIDs = map[string]string{
	"S-1-0-0":        "EVERYONE",
	"S-1-1-0":        "EVERYONE",
	"S-1-5-1":        "DIALUP",
	"S-1-5-2":        "NETWORK",
	"S-1-5-3":        "BATCH",
	"S-1-5-4":        "INTERACTIVE",
	"S-1-5-5":        "LOGON_ID",
	"S-1-5-6":        "SERVICE",
	"S-1-5-7":        "ANONYMOUS",
	"S-1-5-9":        "ENTERPRISE DOMAIN CONTROLLERS",
	"S-1-5-10":       "PRINCIPAL SELF",
	"S-1-5-11":       "AUTHENTICATED USERS",
	"S-1-5-12":       "RESTRICTED",
	"S-1-5-13":       "TERMINAL SERVER USERS",
	"S-1-5-18":       "SYSTEM",
	"S-1-5-19":       "LOCAL SERVICE",
	"S-1-5-20":       "NETWORK SERVICE",
	"S-1-5-32-544":   "BUILTIN\\Administrators",
	"S-1-5-32-545":   "BUILTIN\\Users",
	"S-1-5-32-546":   "BUILTIN\\Guests",
	"S-1-5-32-547":   "BUILTIN\\Power Users",
	"S-1-5-32-548":   "BUILTIN\\Account Operators",
	"S-1-5-32-549":   "BUILTIN\\Server Operators",
	"S-1-5-32-550":   "BUILTIN\\Print Operators",
	"S-1-5-32-551":   "BUILTIN\\Backup Operators",
	"S-1-5-32-555":   "BUILTIN\\Remote Desktop Users",
	"S-1-5-64-10":    "NTLM Authentication",
	"S-1-5-64-14":    "SChannel Authentication",
	"S-1-5-64-21":    "Digest Authentication",
	"S-1-5-80-0":     "NT SERVICES\\ALL SERVICES",
	"S-1-16-0":       "Untrusted Mandatory Level",
	"S-1-16-4096":    "Low Mandatory Level",
	"S-1-16-8192":    "Medium Mandatory Level",
	"S-1-16-8448":    "Medium Plus Mandatory Level",
	"S-1-16-12288":   "High Mandatory Level",
	"S-1-16-16384":   "System Mandatory Level",
	"S-1-16-20480":   "Protected Process Mandatory Level",
}

// 通用 SID 模式 (域 SID + 常见内置 SID + 完整性级别)
var sidRegex = regexp.MustCompile(`S-1-(?:5-(?:21-\d+-\d+-\d+-\d+|18|19|20|32-\d+)|16-\d+)`)

// lookupSID 单个 SID → "DOMAIN\\user"; 失败返回 ""
func lookupSID(sid string) string {
	if v, ok := wellKnownSIDs[sid]; ok {
		return v
	}
	sidVar.mu.Lock()
	if v, ok := sidVar.cache[sid]; ok {
		sidVar.mu.Unlock()
		return v
	}
	sidVar.mu.Unlock()

	name := apiLookupSID(sid)
	sidVar.mu.Lock()
	sidVar.cache[sid] = name
	sidVar.mu.Unlock()
	return name
}

// apiLookupSID 调用 LookupAccountSidW
func apiLookupSID(sid string) string {
	adv := windows.NewLazySystemDLL("advapi32.dll")
	convSid := adv.NewProc("ConvertStringSidToSidW")
	lookup := adv.NewProc("LookupAccountSidW")
	localFree := windows.NewLazySystemDLL("kernel32.dll").NewProc("LocalFree")

	pStr, _ := windows.UTF16PtrFromString(sid)
	var pSid uintptr
	r, _, _ := convSid.Call(uintptr(unsafe.Pointer(pStr)), uintptr(unsafe.Pointer(&pSid)))
	if r == 0 || pSid == 0 {
		return ""
	}
	defer localFree.Call(pSid)

	var nameBuf [256]uint16
	var domainBuf [256]uint16
	var nameLen, domainLen uint32 = 256, 256
	var use uint32
	pName := uintptr(unsafe.Pointer(&nameBuf[0]))
	pDomain := uintptr(unsafe.Pointer(&domainBuf[0]))
	// 第一个参数 NULL = 本机
	r2, _, _ := lookup.Call(0, pSid, pName, uintptr(unsafe.Pointer(&nameLen)),
		pDomain, uintptr(unsafe.Pointer(&domainLen)), uintptr(unsafe.Pointer(&use)))
	if r2 == 0 {
		return ""
	}
	name := windows.UTF16ToString(nameBuf[:nameLen])
	domain := windows.UTF16ToString(domainBuf[:domainLen])
	if domain != "" && domain != name {
		return domain + `\` + name
	}
	return name
}

// translateSIDs 把详情文本里的 SID 替换为 名称 (SID)
func translateSIDs(detail string) string {
	if !strings.Contains(detail, "S-1-") {
		return detail
	}
	return sidRegex.ReplaceAllStringFunc(detail, func(sid string) string {
		if name := lookupSID(sid); name != "" {
			return name + " (" + sid + ")"
		}
		return sid
	})
}
