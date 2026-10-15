//go:build windows

// 事件日志按需加载 (参考 SentinelX 的 shouldDropLowValue 思路)
// 使用 EvtQuery + XPath 过滤, 只读安全/异常相关 EventID
// 不在默认 collectUnifiedActivity 里调用, 仅当用户在 source filter 主动选 "事件日志" 时加载

package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// (wevtapiEL 等已移到 eventlog_scenarios_windows.go 统一管理)


// (const 已在 eventlog_scenarios_windows.go)

// 关键 EventID 白名单 (SentinelX shouldDropLowValue + 安全关键事件)
var eventIDWhitelist = map[string]map[int]string{
	"System": {
		6005: "事件日志服务已启动",
		6006: "事件日志服务已停止",
		6008: "上次关机异常",
		6009: "操作系统版本",
		6013: "系统正常运行时间",
		7045: "新服务安装 (持久化检测关键)",
		7040: "服务启动类型已更改",
		7034: "服务意外终止",
		7023: "服务终止错误",
		7024: "服务终止错误",
		7031: "服务意外终止 (并尝试重启)",
		7022: "服务启动超时",
	},
	"Security": {
		4624: "登录成功",
		4625: "登录失败",
		4634: "注销",
		4647: "用户主动注销",
		4648: "显式凭证登录",
		4672: "特权登录",
		4688: "进程创建",
		4689: "进程退出",
		4720: "用户创建",
		4726: "用户删除",
		4732: "用户加入组",
		4738: "用户账户变更",
		4740: "账户锁定",
		4768: "Kerberos 认证 TGT",
		4769: "Kerberos 服务票据",
		4776: "NTLM 凭据验证",
		4627: "组成员变更",
	},
}

// readTargetedEventLogs 按需读事件日志 (最近 24h, 仅关键 EventID)
func readTargetedEventLogs() []ActivityItem {
	var out []ActivityItem
	cutoff := timeNow().Add(-24 * time.Hour)
	cutoffStr := cutoff.UTC().Format("2006-01-02T15:04:05.000Z")

	for _, logName := range []string{"System", "Security", "Application"} {
		ids, ok := eventIDWhitelist[logName]
		if !ok {
			continue
		}
		var xpath string
		switch logName {
		case "Application":
			xpath = fmt.Sprintf(`*[System[(Level=1 or Level=2) and (TimeCreated[@SystemTime >= '%s'])]]`, cutoffStr)
		default:
			// System, Security: 拉所有事件, 客户端用 ID 白名单过滤
			// (避免 XPath `or` 多 EventID 的复杂语法)
			xpath = fmt.Sprintf(`*[System[TimeCreated[@SystemTime >= '%s']]]`, cutoffStr)
		}

		fmt.Fprintf(os.Stderr, "[eventlog] %s: xpath=%s\n", logName, xpath)
		items := queryEventLogByXPathOld(logName, xpath, ids, true)
		fmt.Fprintf(os.Stderr, "[eventlog] %s: got %d items\n", logName, len(items))
		out = append(out, items...)
	}
	return out
}

func queryEventLogByXPathOld(logName, xpath string, idMap map[int]string, filterById bool) []ActivityItem {
	var out []ActivityItem
	h, err := evtQueryEL(logName, xpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eventlog] %s EvtQuery 失败: %v\n", logName, err)
		return out
	}
	defer evtCloseEL(h)

	readCount := 0
	for {
		handles, err := evtNextEL(h, 100)
		if err != nil || len(handles) == 0 {
			break
		}
		for _, ev := range handles {
			readCount++
			if readCount > 1000 {
				evtCloseEL(ev)
				break
			}
			xmlStr, err := evtRenderEL(ev)
			evtCloseEL(ev)
			if err != nil {
				continue
			}
			eventID := parseEventIDFromXML(xmlStr)
			ts := parseTimeFromXML(xmlStr)
			level := parseLevelFromXML(xmlStr)
			msg := parseMessageFromXML(xmlStr)
			if eventID == 0 {
				continue
			}
			if filterById {
				if _, ok := idMap[eventID]; !ok {
					continue
				}
			}
			desc, _ := idMap[eventID]
			eventName := fmt.Sprintf("%s (EID=%d)", desc, eventID)
			if desc == "" {
				eventName = fmt.Sprintf("EventID=%d (L=%s)", eventID, level)
			}
			out = append(out, ActivityItem{
				Time:   ts,
				Approx: false,
				Type:   "事件日志",
				Event:  eventName,
				Detail: fmt.Sprintf("[%s] %s", logName, msg),
			})
		}
	}
	return out
}

func evtQueryEL(channel, xpath string) (evtHandleEL, error) {
	pCh, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	pXp, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return 0, err
	}
	flags := uint32(EvtQueryChannelPathEL | EvtQueryTolerateQueryErrorsEL)
	r, _, errno := procEvtQueryEL.Call(
		0,
		uintptr(unsafe.Pointer(pCh)),
		uintptr(unsafe.Pointer(pXp)),
		uintptr(flags),
	)
	if r == 0 {
		if errno != nil && errno != syscall_Errno(0) {
			return 0, fmt.Errorf("EvtQuery %s 失败: %v", channel, errno)
		}
		return 0, fmt.Errorf("EvtQuery %s 失败: err=%d", channel, windows.GetLastError())
	}
	return evtHandleEL(r), nil
}

func evtNextEL(h evtHandleEL, max int) ([]evtHandleEL, error) {
	if max <= 0 {
		max = 16
	}
	var got uint32
	arr := make([]evtHandleEL, max)
	r, _, errno := procEvtNextEL.Call(
		uintptr(h),
		uintptr(max),
		uintptr(unsafe.Pointer(&arr[0])),
		0, 0,
		uintptr(unsafe.Pointer(&got)),
	)
	if r == 0 {
		if errno == syscall_Errno(259) { // ERROR_NO_MORE_ITEMS
			return arr[:got], nil
		}
		if errno != nil && errno != syscall_Errno(0) {
			return nil, fmt.Errorf("EvtNext 失败: %v", errno)
		}
		return nil, fmt.Errorf("EvtNext 失败: err=%d", windows.GetLastError())
	}
	return arr[:got], nil
}

func evtRenderEL(h evtHandleEL) (string, error) {
	var bufUsed uint32
	var propCount uint32
	procEvtRenderEL.Call(
		0,
		uintptr(h),
		uintptr(EvtRenderEventXmlEL),
		0, 0,
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if bufUsed == 0 {
		return "", fmt.Errorf("EvtRender: 缓冲区大小未知")
	}
	buf := make([]uint16, bufUsed+1)
	r, _, errno := procEvtRenderEL.Call(
		0,
		uintptr(h),
		uintptr(EvtRenderEventXmlEL),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if r == 0 {
		if errno != nil && errno != syscall_Errno(0) {
			return "", fmt.Errorf("EvtRender 失败: %v", errno)
		}
		return "", fmt.Errorf("EvtRender 失败: err=%d", windows.GetLastError())
	}
	return windows.UTF16ToString(buf), nil
}

func evtCloseEL(h evtHandleEL) {
	procEvtCloseEL.Call(uintptr(h))
}

// 跨包 errno 比较辅助 (避免直接依赖 syscall.Errno 类型在所有 Go 版本可用)
func syscall_Errno(v uintptr) error {
	if v == 0 {
		return nil
	}
	return fmt.Errorf("errno=%d", v)
}

// 抑制未用
var _ = indexOfStr
var _ = parseIntStr

// ============== XML 解析辅助 (复用) ==============




func parseMessageFromXML(xml string) string {
	// 1) <RenderingInfo><Message>...</Message></RenderingInfo>
	start := indexOfStr(xml, "<Message>")
	if start >= 0 {
		start += len("<Message>")
		end := indexOfStr(xml[start:], "</Message>")
		if end >= 0 {
			return CleanText(xml[start : start+end])
		}
	}
	// 2) <EventData><Data>X</Data>...</EventData>
	start = indexOfStr(xml, "<EventData>")
	if start >= 0 {
		end := indexOfStr(xml, "</EventData>")
		if end >= 0 {
			s := xml[start:end]
			var parts []string
			i := 0
			for {
				ds := indexOfStr(s[i:], "<Data")
				if ds < 0 {
					break
				}
				// 找 Data 标签的 >
				gt := indexOfStr(s[i+ds:], ">")
				if gt < 0 {
					break
				}
				de := indexOfStr(s[i+ds+gt:], "</Data>")
				if de < 0 {
					break
				}
				val := s[i+ds+gt+1 : i+ds+gt+de]
				parts = append(parts, val)
				i = i + ds + gt + de + len("</Data>")
			}
			if len(parts) > 0 {
				return CleanText(strings.Join(parts, " | "))
			}
		}
	}
	// 3) 兜底: <Data>X</Data> 直接在根
	var parts []string
	i := 0
	for {
		ds := indexOfStr(xml[i:], "<Data")
		if ds < 0 {
			break
		}
		gt := indexOfStr(xml[i+ds:], ">")
		if gt < 0 {
			break
		}
		de := indexOfStr(xml[i+ds+gt:], "</Data>")
		if de < 0 {
			break
		}
		val := xml[i+ds+gt+1 : i+ds+gt+de]
		parts = append(parts, val)
		i = i + ds + gt + de + len("</Data>")
	}
	if len(parts) > 0 {
		return CleanText(strings.Join(parts, " | "))
	}
	return ""
}


// parseIntStr 解析整数字符串
