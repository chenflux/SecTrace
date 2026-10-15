//go:build windows

// 针对性事件日志读取 (4 个场景)
// 开关机: System 6005/6006/6008/6009/6013/1074
// 网络: NetworkProfile/Operational 10000/10001 + WLAN-AutoConfig/Operational 8001-8005
// 远程登录: Security 4624/4625/4634/4647/4648/4672/4778/4779 (含 RDP=10 / Network=3 重点)
// 计划任务: TaskScheduler/Operational 106/140/141/200/201/202

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapiEL       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQueryEL  = wevtapiEL.NewProc("EvtQuery")
	procEvtNextEL   = wevtapiEL.NewProc("EvtNext")
	procEvtRenderEL = wevtapiEL.NewProc("EvtRender")
	procEvtCloseEL  = wevtapiEL.NewProc("EvtClose")
)

type evtHandleEL uintptr

const (
	EvtQueryChannelPathEL          = 0x1
	EvtQueryTolerateQueryErrorsEL   = 0x1000
	EvtRenderEventXmlEL             = 1
)

// 场景 → 渠道 → EID 白名单
var scenarioChannels = map[string][]channelConfig{
	"power": {
		{Channel: "System", EIDs: []int{6005, 6006, 6008, 6009, 6013, 1074}},
	},
	"network": {
		{Channel: "Microsoft-Windows-NetworkProfile/Operational", EIDs: []int{10000, 10001}},
		{Channel: "Microsoft-Windows-WLAN-AutoConfig/Operational", EIDs: []int{8001, 8002, 8003, 8004, 8005, 11000, 11001, 11004, 11005, 11006, 11010}},
	},
	"rdp": {
		{Channel: "Security", EIDs: []int{4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779}},
	},
	"task": {
		{Channel: "Microsoft-Windows-TaskScheduler/Operational", EIDs: []int{106, 140, 141, 200, 201, 202}},
	},
}

type channelConfig struct {
	Channel string
	EIDs    []int
}

// readScenarioEvents 按场景读事件日志 (最近 24h)
func readScenarioEvents(scenario string) []ActivityItem {
	var out []ActivityItem
	cutoff := timeNow().Add(-24 * time.Hour)
	cfgs, ok := scenarioChannels[scenario]
	if !ok {
		return out
	}
	eidWhitelist := buildEIDWhitelist(scenario)

	for _, cfg := range cfgs {
		var idConds []string
		for _, id := range cfg.EIDs {
			idConds = append(idConds, fmt.Sprintf("EventID=%d", id))
		}
		idXPath := strings.Join(idConds, " or ")
		cutoffStr := cutoff.UTC().Format("2006-01-02T15:04:05.000Z")
		xpath := fmt.Sprintf(`*[System[(%s) and (TimeCreated[@SystemTime >= '%s'])]]`, idXPath, cutoffStr)

		items := queryEventLogEL(cfg.Channel, xpath, eidWhitelist, true)
		if scenario == "rdp" {
			items = filterRDPEvents(items)
		}
		out = append(out, items...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}

func filterRDPEvents(items []ActivityItem) []ActivityItem {
	var out []ActivityItem
	for _, e := range items {
		if strings.Contains(e.Event, "EID=4778") || strings.Contains(e.Event, "EID=4779") ||
			strings.Contains(e.Event, "EID=4634") || strings.Contains(e.Event, "EID=4647") ||
			strings.Contains(e.Event, "EID=4648") || strings.Contains(e.Event, "EID=4672") {
			out = append(out, e)
			continue
		}
		if strings.Contains(e.Event, "EID=4624") || strings.Contains(e.Event, "EID=4625") {
			logonType := extractLogonType(e.Detail)
			if logonType == "10" || logonType == "3" || logonType == "9" || logonType == "2" {
				e.Event = e.Event + " [LogonType=" + logonType + "]"
				out = append(out, e)
			}
		}
	}
	return out
}

func extractLogonType(detail string) string {
	idx := strings.Index(detail, "LogonType=")
	if idx >= 0 {
		rest := detail[idx+len("LogonType="):]
		end := strings.Index(rest, "|")
		if end > 0 {
			return strings.TrimSpace(rest[:end])
		}
		return strings.TrimSpace(rest)
	}
	return ""
}

func buildEIDWhitelist(scenario string) map[int]string {
	m := map[int]string{}
	switch scenario {
	case "power":
		m[6005] = "事件日志服务已启动"
		m[6006] = "事件日志服务已停止"
		m[6008] = "上次关机异常"
		m[6009] = "操作系统版本"
		m[6013] = "系统正常运行时间"
		m[1074] = "用户主动关机/重启 (含原因)"
	case "network":
		m[10000] = "网络已连接"
		m[10001] = "网络已断开"
		m[8001] = "WLAN 关联"
		m[8002] = "WLAN 解除关联"
		m[8003] = "WLAN 连接"
		m[8004] = "WLAN 断开"
		m[8005] = "WLAN 扫描完成"
		m[11000] = "无线关联状态变化"
		m[11001] = "无线连接成功"
		m[11004] = "无线安全成功"
		m[11005] = "无线安全失败"
		m[11006] = "无线连接尝试"
		m[11010] = "无线漫游"
	case "rdp":
		m[4624] = "登录成功"
		m[4625] = "登录失败"
		m[4634] = "注销"
		m[4647] = "用户主动注销"
		m[4648] = "显式凭证登录"
		m[4672] = "特权登录"
		m[4778] = "RDP 会话重连"
		m[4779] = "RDP 会话断开"
	case "task":
		m[106] = "任务已创建"
		m[140] = "任务已更新"
		m[141] = "任务已删除"
		m[200] = "任务已启动"
		m[201] = "任务已完成"
		m[202] = "任务已终止"
	}
	return m
}

func scenarioTypeLabel(scenario string) string {
	switch scenario {
	case "power":
		return "开关机"
	case "network":
		return "网络"
	case "rdp":
		return "登录"
	case "task":
		return "计划任务"
	}
	return "事件"
}

func queryEventLogEL(channel, xpath string, eidMap map[int]string, filterByEID bool) []ActivityItem {
	var out []ActivityItem
	h, err := evtQueryEL_Query(channel, xpath)
	if err != nil {
		return out
	}
	defer evtCloseEL_Close(h)

	readCount := 0
	for {
		handles, err := evtNextEL_Next(h, 100)
		if err != nil || len(handles) == 0 {
			break
		}
		for _, ev := range handles {
			readCount++
			if readCount > 2000 {
				evtCloseEL_Close(ev)
				break
			}
			xmlStr, err := evtRenderEL_Render(ev)
			evtCloseEL_Close(ev)
			if err != nil {
				continue
			}
			eventID := parseEventIDFromXML(xmlStr)
			ts := parseTimeFromXML(xmlStr)
			level := parseLevelFromXML(xmlStr)
			fields := parseEventDataFields(xmlStr)
			if eventID == 0 {
				continue
			}
			if filterByEID {
				if _, ok := eidMap[eventID]; !ok {
					continue
				}
			}
			desc, _ := eidMap[eventID]
			eventName := fmt.Sprintf("%s (EID=%d)", desc, eventID)
			if desc == "" {
				eventName = fmt.Sprintf("EventID=%d (L=%s)", eventID, level)
			}
			detail := formatDetailForScenario(extractScenario(channel, eidMap), eventID, fields)
			_ = level
			out = append(out, ActivityItem{
				Time:   ts,
				Approx: false,
				Type:   scenarioTypeLabel(extractScenario(channel, eidMap)),
				Event:  eventName,
				Detail: detail,
			})
		}
	}
	return out
}

// extractScenario 从 eidMap 的内容反推场景 (简单)
func extractScenario(channel string, eidMap map[int]string) string {
	for s, cfgs := range scenarioChannels {
		for _, cfg := range cfgs {
			if cfg.Channel == channel {
				_ = s
				// Check if the eidMap has any of cfg's EIDs
				for _, id := range cfg.EIDs {
					if _, ok := eidMap[id]; ok {
						return s
					}
				}
			}
		}
	}
	return ""
}

func formatDetailForScenario(scenario string, eid int, fields map[string]string) string {
	switch scenario {
	case "power":
		switch eid {
		case 1074:
			return fmt.Sprintf("用户: %s | 进程: %s | 原因: %s | 类型: %s",
				valueOr(fields, "param1", "?"),
				valueOr(fields, "param2", "?"),
				valueOr(fields, "param5", "?"),
				valueOr(fields, "param4", "?"))
		case 6008:
			return fmt.Sprintf("上次关机异常: %s | 内核状态: %s",
				valueOr(fields, "BugcheckDescription", "?"),
				valueOr(fields, "BugcheckCode", "?"))
		case 6013:
			uptime := valueOr(fields, "data[4]", "?")
			return fmt.Sprintf("系统正常运行: %s 秒", uptime)
		}
		return fieldsToString(fields)

	case "network":
		if eid == 10000 || eid == 10001 {
			return fmt.Sprintf("配置: %s | 描述: %s | 类别: %s",
				valueOr(fields, "ProfileName", "?"),
				valueOr(fields, "Description", "?"),
				valueOr(fields, "Category", "?"))
		}
		return fmt.Sprintf("SSID: %s | 接口: %s",
			valueOr(fields, "SSID", valueOr(fields, "ProfileName", "?")),
			valueOr(fields, "Interface", valueOr(fields, "InterfaceGuid", "?")))

	case "rdp":
		switch eid {
		case 4672:
			return fmt.Sprintf("用户: %s | 域: %s | SID: %s | LogonId: %s",
				valueOr(fields, "SubjectUserName", "?"),
				valueOr(fields, "SubjectDomainName", "?"),
				valueOr(fields, "SubjectUserSid", "?"),
				valueOr(fields, "SubjectLogonId", "?"))
		case 4778, 4779:
			return fmt.Sprintf("用户: %s | 域: %s | 源IP: %s | 会话ID: %s",
				valueOr(fields, "User", "?"),
				valueOr(fields, "Domain", "?"),
				valueOr(fields, "SourceNetworkAddress", "?"),
				valueOr(fields, "SessionId", "?"))
		case 4634, 4647, 4648:
			return fmt.Sprintf("用户: %s | 域: %s | 登录ID: %s | 登录类型: %s",
				valueOr(fields, "TargetUserName", "?"),
				valueOr(fields, "TargetDomainName", "?"),
				valueOr(fields, "TargetLogonId", "?"),
				valueOr(fields, "LogonType", "?"))
		}
		return fmt.Sprintf("用户: %s | 域: %s | 源IP: %s | 登录类型: %s | 认证: %s",
			valueOr(fields, "TargetUserName", "?"),
			valueOr(fields, "TargetDomainName", "?"),
			valueOr(fields, "IpAddress", valueOr(fields, "WorkstationName", "本地")),
			valueOr(fields, "LogonType", "?"),
			valueOr(fields, "AuthenticationPackageName", "?"))

	case "task":
		if eid == 106 || eid == 140 || eid == 141 {
			return fmt.Sprintf("任务: %s", valueOr(fields, "TaskName", valueOr(fields, "TaskPath", "?")))
		}
		if eid == 200 || eid == 201 || eid == 202 {
			return fmt.Sprintf("任务: %s | 动作: %s",
				valueOr(fields, "TaskName", valueOr(fields, "TaskPath", "?")),
				valueOr(fields, "ActionName", ""))
		}
		return fieldsToString(fields)
	}
	return fieldsToString(fields)
}

func valueOr(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

func fieldsToString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	var parts []string
	for k, v := range m {
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " | ")
}

func parseEventDataFields(xml string) map[string]string {
	out := map[string]string{}
	start := indexOfStr(xml, "<EventData>")
	if start >= 0 {
		end := indexOfStr(xml, "</EventData>")
		if end >= 0 {
			parseDataFieldsInRange(xml[start:end], out)
			return out
		}
	}
	parseDataFieldsInRange(xml, out)
	return out
}

func parseDataFieldsInRange(s string, out map[string]string) {
	i := 0
	idx := 0
	loopCount := 0
	for {
		loopCount++
		if loopCount <= 3 {
		}
		if loopCount > 50 {
			break
		}
		ds := indexOfStr(s[i:], "<Data")
		if ds < 0 {
			break
		}
		gt := indexOfStr(s[i+ds:], ">")
		if gt < 0 {
			break
		}
		tagStart := i + ds
		tagEnd := i + ds + gt
		name := extractAttr(s[tagStart:tagEnd], "Name")
		de := indexOfStr(s[i+ds+gt:], "</Data>")
		if de < 0 {
			break
		}
		value := s[i+ds+gt+1 : i+ds+gt+de]
		value = decodeHTMLEscapes(value)
		if name != "" {
			out[name] = value
		} else {
			out[fmt.Sprintf("data[%d]", idx)] = value
			idx++
		}
		i = i + ds + gt + de + len("</Data>")
	}
}

func extractAttr(tag, attr string) string {
	for _, q := range []byte{34, 39} {
		key1 := " " + attr + "=" + string(q)
		key2 := attr + "=" + string(q)
		if i := indexOfStr(tag, key1); i >= 0 {
			start := i + len(key1)
			if end := indexOfStr(tag[start:], string(q)); end >= 0 {
				return tag[start : start+end]
			}
		}
		if i := indexOfStr(tag, key2); i >= 0 {
			start := i + len(key2)
			if end := indexOfStr(tag[start:], string(q)); end >= 0 {
				return tag[start : start+end]
			}
		}
	}
	return ""
}

func decodeHTMLEscapes(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&apos;", "'")
	return s
}

// ============== EvtQuery API 封装 (用 golang.org/x/sys/windows 的 LazyProc) ==============

func evtQueryEL_Query(channel, xpath string) (evtHandleEL, error) {
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
		if errno != nil && errno != windowsErrno(0) {
			return 0, fmt.Errorf("EvtQuery %s 失败: %v", channel, errno)
		}
		return 0, fmt.Errorf("EvtQuery %s 失败: err=%d", channel, windows.GetLastError())
	}
	return evtHandleEL(r), nil
}

func evtNextEL_Next(h evtHandleEL, max int) ([]evtHandleEL, error) {
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
		if errno == windowsErrno(259) {
			return arr[:got], nil
		}
		if errno != nil && errno != windowsErrno(0) {
			return nil, fmt.Errorf("EvtNext 失败: %v", errno)
		}
		return nil, fmt.Errorf("EvtNext 失败: err=%d", windows.GetLastError())
	}
	return arr[:got], nil
}

func evtRenderEL_Render(h evtHandleEL) (string, error) {
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
		if errno != nil && errno != windowsErrno(0) {
			return "", fmt.Errorf("EvtRender 失败: %v", errno)
		}
		return "", fmt.Errorf("EvtRender 失败: err=%d", windows.GetLastError())
	}
	return windows.UTF16ToString(buf), nil
}

func evtCloseEL_Close(h evtHandleEL) {
	procEvtCloseEL.Call(uintptr(h))
}

// windowsErrno 包装 (避免直接 syscall.Errno 类型比较在不同 Go 版本报错)
func windowsErrno(v uintptr) error {
	if v == 0 {
		return nil
	}
	return fmt.Errorf("errno=%d", v)
}

// 公共 XML 解析辅助 (从 eventlog_windows.go 复用)
func indexOfStr(s, sub string) int {
	if sub == "" {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func parseIntStr(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func parseEventIDFromXML(xml string) int {
	start := indexOfStr(xml, "<EventID>")
	if start < 0 {
		start = indexOfStr(xml, "<EventID ")
		if start < 0 {
			return 0
		}
		gIdx := indexOfStr(xml[start:], ">")
		if gIdx < 0 {
			return 0
		}
		start = start + gIdx + 1
	} else {
		start += len("<EventID>")
	}
	end := indexOfStr(xml[start:], "</EventID>")
	if end < 0 {
		return 0
	}
	return parseIntStr(xml[start : start+end])
}

func parseTimeFromXML(xml string) time.Time {
	// XML 属性可能是单引号或双引号, 两种都试
	for _, q := range []byte{34, 39} {
		tag := `<TimeCreated SystemTime=` + string(q)
		idx := indexOfStr(xml, tag)
		if idx < 0 {
			continue
		}
		start := idx + len(tag)
		end := indexOfStr(xml[start:], string(q))
		if end < 0 {
			continue
		}
		s := xml[start : start+end]
		for _, layout := range []string{
			"2006-01-02T15:04:05.9999999Z",
			"2006-01-02T15:04:05Z",
			time.RFC3339Nano, time.RFC3339,
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.Local()
			}
		}
	}
	return time.Time{}
}

func parseLevelFromXML(xml string) string {
	start := indexOfStr(xml, "<Level>")
	if start < 0 {
		return ""
	}
	start += len("<Level>")
	end := indexOfStr(xml[start:], "</Level>")
	if end < 0 {
		return ""
	}
	return xml[start : start+end]
}
