//go:build windows

package main

// Windows 事件日志 (Legacy ReadEventLog API)
// 使用 advapi32.dll 的 ReadEventLog 函数, 简化版

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32            = windows.NewLazySystemDLL("advapi32.dll")
	procOpenEventLog    = advapi32.NewProc("OpenEventLogW")
	procReadEventLog    = advapi32.NewProc("ReadEventLogW")
	procCloseEventLog   = advapi32.NewProc("CloseEventLog")
)

// EVENTLOGRECORD 结构 (简化版, 只取必要字段)
type eventLogRecord struct {
	Length        uint32
	Reserved      uint32
	RecordNumber  uint32
	TimeGenerated uint32
	TimeWritten   uint32
	EventID       uint32
	EventType     uint16
	NumStrings    uint16
	EventCategory uint16
	ReservedFlags uint16
	ClosingRecordNumber uint32
	StringOffset  uint32
	UserSidLength uint32
	UserSidOffset uint32
	DataLength    uint32
	DataOffset    uint32
}

type EventInfo struct {
	LogName string
	Time    time.Time
	Level   string
	Source  string
	EventID int
	Message string
}

// EventIDNameMap 常见事件 ID -> 含义
var EventIDNameMap = map[string]map[int]string{
	"System": {
		6005: "系统启动", 6006: "系统关闭", 6008: "意外关机",
		1074: "用户主动关机/重启", 7036: "服务状态变更",
		7045: "服务安装", 10016: "DCOM 错误",
	},
	"Application": {
		1000: "应用崩溃", 1001: "Windows 错误报告",
	},
	"Security": {
		4624: "登录成功", 4625: "登录失败", 4634: "注销",
		4648: "显式凭证登录", 4672: "特权登录", 4688: "进程创建",
		4689: "进程退出", 4720: "用户创建", 4726: "用户删除",
		4732: "用户加入组", 4738: "用户账户变更",
		4740: "账户锁定", 4768: "Kerberos 认证 TGT",
		4769: "Kerberos 服务票据", 4776: "NTLM 凭据验证",
		5140: "网络共享访问", 5145: "网络共享访问详情",
	},
}

const (
	eventLogSequential = 0x0001
	eventLogBackwards  = 0x0008
	eventLogSucceed    = 0x0000
	eventPartialReg    = 0x0001
)

func openEventLog(name string) (syscall.Handle, error) {
	pName, _ := syscall.UTF16PtrFromString(name)
	h, _, errno := procOpenEventLog.Call(0, uintptr(unsafe.Pointer(pName)))
	if h == 0 {
		if errno != nil && errno != syscall.Errno(0) {
			return 0, fmt.Errorf("OpenEventLog %s 失败: %v", name, errno)
		}
		return 0, fmt.Errorf("OpenEventLog %s 失败: errno=%d", name, windows.GetLastError())
	}
	return syscall.Handle(h), nil
}

func closeEventLog(h syscall.Handle) {
	procCloseEventLog.Call(uintptr(h))
}

func readEventLog(logName string, max int) ([]EventInfo, error) {
	h, err := openEventLog(logName)
	if err != nil {
		return nil, err
	}
	defer closeEventLog(h)

	var events []EventInfo
	buf := make([]byte, 64*1024) // 64KB buffer
	var readBytes, minBytes uint32

	for len(events) < max {
		// ReadEventLog: 第二个 0 = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ
		r, _, errno := procReadEventLog.Call(
			uintptr(h),
			uintptr(eventLogSequential|eventLogBackwards),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&readBytes)),
			uintptr(unsafe.Pointer(&minBytes)),
		)
		if r == 0 {
			if errno == syscall.Errno(38) || errno == syscall.Errno(259) {
				// ERROR_HANDLE_EOF or ERROR_NO_MORE_FILES
				break
			}
			if errno != nil && errno != syscall.Errno(0) {
				return events, fmt.Errorf("ReadEventLog 失败: %v", errno)
			}
			break
		}
		if readBytes == 0 {
			break
		}
		// 解析记录
		offset := uint32(0)
		recSize := uint32(unsafe.Sizeof(eventLogRecord{}))
		for offset+recSize <= uint32(readBytes) {
			rec := (*eventLogRecord)(unsafe.Pointer(&buf[offset]))
			// 字符串起始位置
			strOff := offset + rec.StringOffset
			strArr := []string{}
			if rec.NumStrings > 0 {
				strArr = readStrings(buf, strOff, rec.NumStrings)
			}
			// 源名称: 在 UserSidOffset 之后, 紧跟 SID, 然后是 SourceName
			var source string
			// SourceName 在 UserSidOffset + UserSidLength 处 (字节对齐)
			afterSid := offset + rec.UserSidOffset + rec.UserSidLength
			if afterSid+2 <= uint32(readBytes) {
				// Unicode 字符串, 取 N 字节直到 \x00\x00
				source = readUnicodeString(buf, afterSid, uint32(readBytes))
			}
			// ComputerName 在 SourceName 后
			var computer string
			if source != "" {
				srcBytes := uint32(utf16Len(source)*2 + 2)
				compStart := afterSid + srcBytes
				if compStart+2 <= uint32(readBytes) {
					computer = readUnicodeString(buf, compStart, uint32(readBytes))
				}
			}
			_ = computer

			eventID := int(rec.EventID & 0xFFFF)
			level := levelFromType(rec.EventType)

			t := time.Unix(int64(rec.TimeGenerated), 0).Local()
			msg := strings.Join(strArr, " | ")
			msg = CleanText(msg)
			if msg == "" {
				msg = fmt.Sprintf("EventID=%d", eventID)
			}
			if m, ok := EventIDNameMap[logName]; ok {
				if name, ok := m[eventID]; ok {
					msg = name + " | " + msg
				}
			}

			events = append(events, EventInfo{
				LogName: logName,
				Time:    t,
				Level:   level,
				Source:  source,
				EventID: eventID,
				Message: msg,
			})

			if len(events) >= max {
				break
			}

			offset += rec.Length
		}
	}
	return events, nil
}

func levelFromType(t uint16) string {
	switch t {
	case 0:
		return "Success"
	case 1:
		return "Error"
	case 2:
		return "Warning"
	case 4:
		return "Information"
	case 8:
		return "AuditSuccess"
	case 16:
		return "AuditFailure"
	default:
		return fmt.Sprintf("Type=%d", t)
	}
}

func readStrings(buf []byte, offset uint32, count uint16) []string {
	var strs []string
	pos := offset
	for i := uint16(0); i < count; i++ {
		// 找 \x00 结束 (字符串以 \x00\x00 终止 for 旧 API, 但 strings 是 \x00 分隔的 ASCII)
		start := pos
		for pos < uint32(len(buf)) && buf[pos] != 0 {
			pos++
		}
		if pos > start {
			strs = append(strs, string(buf[start:pos]))
		}
		pos++ // 跳过分隔符
		if pos >= uint32(len(buf)) {
			break
		}
	}
	return strs
}

func readUnicodeString(buf []byte, offset, total uint32) string {
	if offset+2 > total {
		return ""
	}
	// 找到 NUL 终止符 (0x00 0x00)
	end := offset
	for end+1 < total {
		if buf[end] == 0 && buf[end+1] == 0 {
			break
		}
		end += 2
	}
	if end == offset {
		return ""
	}
	u16 := make([]uint16, 0, (end-offset)/2)
	for i := offset; i+1 < end; i += 2 {
		u16 = append(u16, uint16(buf[i])|uint16(buf[i+1])<<8)
	}
	return syscall.UTF16ToString(u16)
}

func utf16Len(s string) int {
	return len([]rune(s))
}
