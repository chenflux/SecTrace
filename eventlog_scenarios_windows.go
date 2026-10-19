//go:build windows

// 事件日志场景化读取 (encoding/xml 重写版)
//   power:   System 6005/6006/6008/6009/6013/1074
//   network: NetworkProfile 10000/10001 + WLAN-AutoConfig 800x/1100x
//   rdp:     Security 4624/4625/... + TerminalServices-LocalSessionManager 21/24/25
//   task:    TaskScheduler 106/140/141/200/201/202
//   ps:      PowerShell/Operational 4103/4104 (脚本块/管道)
//
// 读取策略: XPath 服务端过滤 (EID + 时间窗), 客户端兜底白名单
// 详情: EventData 命名字段映射 + 位置型 data[N] + SID 翻译

package main

import (
	"encoding/xml"
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
	EvtQueryChannelPathEL           = 0x1
	EvtQueryTolerateQueryErrorsEL   = 0x1000
	EvtRenderEventXmlEL             = 1
	// 注: EvtQueryReverseDirection(0x2) 在部分 Windows 上报
	// "parameter is incorrect", 不使用; 时间倒序在 Go 端排序
)

// evDataXML EventData 里的 <Data Name="X">Y</Data> 或匿名 <Data>Y</Data>
type evDataXML struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// evXML 事件 XML 结构 (encoding/xml 原生兼容单/双引号属性)
type evXML struct {
	System struct {
		EventID     int    `xml:"EventID"`
		Level       int    `xml:"Level"`
		Provider    string `xml:"Provider"`
		Computer    string `xml:"Computer"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []evDataXML `xml:"Data"`
	} `xml:"EventData"`
}

// parseEventXML 解析事件 XML → (eid, time, level, fields)
// fields: 命名字段 + 位置型 data[N]
func parseEventXML(xmlStr string) (int, time.Time, int, map[string]string) {
	var ev evXML
	if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
		return 0, time.Time{}, 0, nil
	}
	var t time.Time
	if s := ev.System.TimeCreated.SystemTime; s != "" {
		for _, layout := range []string{
			"2006-01-02T15:04:05.9999999Z",
			"2006-01-02T15:04:05Z",
			time.RFC3339Nano, time.RFC3339,
		} {
			if pt, err := time.Parse(layout, s); err == nil {
				t = pt.Local()
				break
			}
		}
	}
	fields := map[string]string{}
	idx := 0
	for _, d := range ev.EventData.Data {
		v := strings.TrimSpace(d.Value)
		if d.Name != "" {
			fields[d.Name] = v
		} else {
			fields[fmt.Sprintf("data[%d]", idx)] = v
			idx++
		}
	}
	return ev.System.EventID, t, ev.System.Level, fields
}

// ---------- 场景定义 ----------

type channelConfig struct {
	Channel string
	EIDs    []int
}

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
		{Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", EIDs: []int{21, 24, 25, 39}},
	},
	"task": {
		{Channel: "Microsoft-Windows-TaskScheduler/Operational", EIDs: []int{106, 140, 141, 200, 201, 202}},
	},
	"ps": {
		{Channel: "Microsoft-Windows-PowerShell/Operational", EIDs: []int{4103, 4104, 400, 600}},
	},
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
		m[21] = "RDP 会话登录"
		m[24] = "RDP 会话断开"
		m[25] = "RDP 会话重连"
		m[39] = "会话断开 (管理员)"
	case "task":
		m[106] = "任务已创建"
		m[140] = "任务已更新"
		m[141] = "任务已删除"
		m[200] = "任务已启动"
		m[201] = "任务已完成"
		m[202] = "任务已终止"
	case "ps":
		m[4103] = "PowerShell 管道执行"
		m[4104] = "PowerShell 脚本块"
		m[400] = "PowerShell 引擎启动"
		m[600] = "PowerShell 命令行"
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
	case "ps":
		return "程序运行"
	}
	return "事件"
}

// readScenarioEvents 按场景读事件日志 (最近 24h, XPath 服务端过滤)
func readScenarioEvents(scenario string) []ActivityItem {
	var out []ActivityItem
	cutoff := timeNow().Add(-24 * time.Hour)
	cfgs, ok := scenarioChannels[scenario]
	if !ok {
		return out
	}
	eidMap := buildEIDWhitelist(scenario)

	for _, cfg := range cfgs {
		xpath := buildScenarioXPath(cfg.EIDs, cutoff)
		items := queryEventLogEL(cfg.Channel, xpath, eidMap, scenario)
		out = append(out, items...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Time.After(out[j].Time)
	})
	return out
}

// buildScenarioXPath 构造服务端过滤 XPath (EID or 列表 + 时间窗)
func buildScenarioXPath(eids []int, cutoff time.Time) string {
	var idConds []string
	for _, id := range eids {
		idConds = append(idConds, fmt.Sprintf("EventID=%d", id))
	}
	cutoffStr := cutoff.UTC().Format("2006-01-02T15:04:05.000Z")
	return fmt.Sprintf(`*[System[(%s) and TimeCreated[@SystemTime >= '%s']]]`,
		strings.Join(idConds, " or "), cutoffStr)
}

// queryEventLogEL 拉取并解析一个渠道
func queryEventLogEL(channel, xpath string, eidMap map[int]string, scenario string) []ActivityItem {
	var out []ActivityItem
	h, err := evtQueryEL_Query(channel, xpath)
	if err != nil {
		// XPath 过滤失败时回退为纯时间窗 (客户端白名单)
		cutoff := timeNow().Add(-24 * time.Hour)
		fallback := fmt.Sprintf(`*[System[TimeCreated[@SystemTime >= '%s']]]`,
			cutoff.UTC().Format("2006-01-02T15:04:05.000Z"))
		h, err = evtQueryEL_Query(channel, fallback)
		if err != nil {
			return out
		}
	}
	defer evtCloseEL_Close(h)

	const hardCap = 5000 // 单渠道读取上限
	read := 0
	for read < hardCap {
		handles, err := evtNextEL_Next(h, 100)
		if err != nil || len(handles) == 0 {
			break
		}
		done := true
		for _, ev := range handles {
			read++
			if read > hardCap {
				evtCloseEL_Close(ev)
				continue
			}
			xmlStr, rerr := evtRenderEL_Render(ev)
			evtCloseEL_Close(ev)
			if rerr != nil {
				continue
			}
			eid, ts, level, fields := parseEventXML(xmlStr)
			if eid == 0 {
				continue
			}
			if _, ok := eidMap[eid]; !ok {
				continue // 客户端白名单兜底
			}
			desc := eidMap[eid]
			eventName := fmt.Sprintf("%s (EID=%d)", desc, eid)
			detail := formatDetailForScenario(scenario, channel, eid, fields)
			out = append(out, ActivityItem{
				Time:   ts,
				Type:   scenarioTypeLabel(scenario),
				Event:  eventName,
				Detail: fmt.Sprintf("[L%d] %s", level, detail),
			})
			done = false
		}
		if done && len(handles) > 0 && read >= hardCap {
			break
		}
	}
	return out
}

// formatDetailForScenario 场景化详情 (关键字段提取 + SID 翻译)
func formatDetailForScenario(scenario, channel string, eid int, f map[string]string) string {
	var d string
	// TerminalServices-LocalSessionManager 频道优先
	if strings.Contains(channel, "TerminalServices") {
		switch eid {
		case 21, 24, 25, 39:
			d = fmt.Sprintf("用户: %s | 源IP: %s | 会话: RDP-Tcp#%s",
				val(f, "User", "Param1"), val(f, "Address", "Param3"), val(f, "SessionID", "Param2"))
			return translateSIDs(d)
		}
	}
	if strings.Contains(channel, "PowerShell") {
		switch eid {
		case 4104:
			script := val(f, "ScriptBlockText", "data[1]")
			if len(script) > 300 {
				script = script[:300] + " ..."
			}
			d = fmt.Sprintf("路径: %s | 脚本: %s", val(f, "Path", "data[0]"), script)
		case 4103:
			payload := val(f, "Payload", "")
			if len(payload) > 300 {
				payload = payload[:300] + " ..."
			}
			d = fmt.Sprintf("管道: %s", payload)
		case 400:
			d = fmt.Sprintf("主机版本: %s | RunspaceID: %s",
				val(f, "HostVersion", "data[0]"), val(f, "RunspaceId", ""))
		case 600:
			d = fmt.Sprintf("命令行: %s", val(f, "ContextInfo", "EventData"))
			if len(d) > 320 {
				d = d[:320] + " ..."
			}
		}
		return translateSIDs(d)
	}

	switch scenario {
	case "power":
		switch eid {
		case 1074:
			d = fmt.Sprintf("用户: %s | 进程: %s | 原因: %s | 类型: %s",
				val(f, "param1", "data[0]"), val(f, "param2", "data[1]"),
				val(f, "param5", "data[4]"), val(f, "param4", "data[3]"))
		case 6013:
			d = fmt.Sprintf("正常运行: %s 秒", val(f, "data[4]", "Uptime"))
		default:
			d = fieldsToString(f)
		}
	case "network":
		if eid == 10000 || eid == 10001 {
			d = fmt.Sprintf("配置: %s | 描述: %s | 类别: %s",
				val(f, "Name", "ProfileName"), val(f, "Description", ""), val(f, "Category", "data[5]"))
		} else {
			d = fmt.Sprintf("SSID: %s | 接口: %s",
				val(f, "SSID", "ProfileName"), val(f, "Interface", "InterfaceGuid"))
		}
	case "rdp":
		switch eid {
		case 4672:
			d = fmt.Sprintf("用户: %s | 域: %s | SID: %s | LogonId: %s",
				val(f, "SubjectUserName", ""), val(f, "SubjectDomainName", ""),
				val(f, "SubjectUserSid", ""), val(f, "SubjectLogonId", ""))
		case 4778, 4779:
			d = fmt.Sprintf("用户: %s | 域: %s | 源IP: %s | 会话ID: %s",
				val(f, "AccountName", "User"), val(f, "AccountDomain", "Domain"),
				val(f, "ClientName", "SourceNetworkAddress"), val(f, "SessionId", ""))
		case 4634, 4647, 4648:
			d = fmt.Sprintf("用户: %s | 域: %s | 登录ID: %s | 登录类型: %s",
				val(f, "TargetUserName", ""), val(f, "TargetDomainName", ""),
				val(f, "TargetLogonId", ""), val(f, "LogonType", ""))
		default: // 4624/4625
			d = fmt.Sprintf("用户: %s | 域: %s | 源IP: %s | 登录类型: %s | 认证: %s | 进程: %s",
				val(f, "TargetUserName", ""), val(f, "TargetDomainName", ""),
				val(f, "IpAddress", val(f, "WorkstationName", "本地")),
				val(f, "LogonType", "?"), val(f, "AuthenticationPackageName", ""),
				val(f, "ProcessName", ""))
		}
	case "task":
		name := val(f, "TaskName", val(f, "TaskPath", "data[0]"))
		switch eid {
		case 106, 140, 141:
			d = fmt.Sprintf("任务: %s | 用户: %s", name, val(f, "UserName", "data[1]"))
		default:
			d = fmt.Sprintf("任务: %s | 动作: %s | 进程: %s",
				name, val(f, "ActionName", ""), val(f, "ProcessName", "data[1]"))
		}
	default:
		d = fieldsToString(f)
	}
	return translateSIDs(d)
}

// val 多候选键取值
func val(f map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := f[k]; ok && v != "" {
			return v
		}
	}
	return "?"
}

func fieldsToString(f map[string]string) string {
	if len(f) == 0 {
		return ""
	}
	var parts []string
	for k, v := range f {
		if v == "" || strings.HasPrefix(k, "data[") {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	if len(parts) == 0 {
		// 只有位置型数据时拼接
		for i := 0; ; i++ {
			k := fmt.Sprintf("data[%d]", i)
			if v, ok := f[k]; ok && v != "" {
				parts = append(parts, v)
				continue
			}
			break
		}
	}
	s := strings.Join(parts, " | ")
	if len(s) > 400 {
		s = s[:400] + " ..."
	}
	return s
}

// ---------- EvtQuery API 封装 ----------

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
	r, _, errno := procEvtQueryEL.Call(0,
		uintptr(unsafe.Pointer(pCh)), uintptr(unsafe.Pointer(pXp)), uintptr(flags))
	if r == 0 {
		if errno != nil && errno != windowsErrno(0) {
			return 0, fmt.Errorf("EvtQuery %s: %v", channel, errno)
		}
		return 0, fmt.Errorf("EvtQuery %s: err=%d", channel, windows.GetLastError())
	}
	return evtHandleEL(r), nil
}

func evtNextEL_Next(h evtHandleEL, max int) ([]evtHandleEL, error) {
	if max <= 0 {
		max = 16
	}
	var got uint32
	arr := make([]evtHandleEL, max)
	r, _, errno := procEvtNextEL.Call(uintptr(h), uintptr(max),
		uintptr(unsafe.Pointer(&arr[0])), 0, 0, uintptr(unsafe.Pointer(&got)))
	if r == 0 {
		if errno == windowsErrno(259) { // ERROR_NO_MORE_ITEMS
			return arr[:got], nil
		}
		if errno != nil && errno != windowsErrno(0) {
			return nil, fmt.Errorf("EvtNext: %v", errno)
		}
		return nil, fmt.Errorf("EvtNext: err=%d", windows.GetLastError())
	}
	return arr[:got], nil
}

func evtRenderEL_Render(h evtHandleEL) (string, error) {
	var bufUsed uint32
	var propCount uint32
	procEvtRenderEL.Call(0, uintptr(h), uintptr(EvtRenderEventXmlEL), 0, 0,
		uintptr(unsafe.Pointer(&bufUsed)), uintptr(unsafe.Pointer(&propCount)))
	if bufUsed == 0 {
		return "", fmt.Errorf("EvtRender: 缓冲区未知")
	}
	buf := make([]uint16, bufUsed+1)
	r, _, errno := procEvtRenderEL.Call(0, uintptr(h), uintptr(EvtRenderEventXmlEL),
		uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufUsed)), uintptr(unsafe.Pointer(&propCount)))
	if r == 0 {
		if errno != nil && errno != windowsErrno(0) {
			return "", fmt.Errorf("EvtRender: %v", errno)
		}
		return "", fmt.Errorf("EvtRender: err=%d", windows.GetLastError())
	}
	return windows.UTF16ToString(buf), nil
}

func evtCloseEL_Close(h evtHandleEL) {
	procEvtCloseEL.Call(uintptr(h))
}

// windowsErrno errno 包装
func windowsErrno(v uintptr) error {
	if v == 0 {
		return nil
	}
	return fmt.Errorf("errno=%d", v)
}
