package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsAdmin 检查是否以管理员权限运行
// 用 3 种方式按顺序尝试, 只要任一成功就返回 true:
//   1. shell32.IsUserAnAdmin (推荐, Vista+ 通用)
//   2. GetTokenInformation TokenElevationType (TokenElevationTypeFull=2)
//   3. 尝试打开 SAM 文件 (最后的回退, 旧 Win 上仍可工作)
func IsAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// 方法 1: shell32.IsUserAnAdmin
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	if proc := shell32.NewProc("IsUserAnAdmin"); proc != nil {
		r, _, _ := proc.Call()
		if r != 0 {
			return true
		}
	}
	// 方法 2: GetTokenInformation TokenElevationType
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTokenInfo := advapi32.NewProc("GetTokenInformation")
	getCurrentProc := kernel32.NewProc("GetCurrentProcess")
	if getTokenInfo != nil && getCurrentProc != nil {
		var token windows.Token
		h, _, _ := getCurrentProc.Call()
		if h != 0 {
			_ = windows.OpenProcessToken(windows.Handle(h), windows.TOKEN_QUERY, &token)
			if token != 0 {
				defer token.Close()
				var elevationType uint32
				var retLen uint32
				r, _, _ := getTokenInfo.Call(
					uintptr(token),
					20, // TokenElevationType
					uintptr(unsafe.Pointer(&elevationType)),
					4,
					uintptr(unsafe.Pointer(&retLen)),
				)
				if r != 0 && (elevationType == 2 /*TokenElevationTypeFull*/) {
					return true
				}
			}
		}
	}
	// 方法 3 (最后回退): 打开 SAM
	f, err := os.Open(`C:\Windows\System32\config\SAM`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// GetEnv 获取环境变量, 失败返回空字符串
func GetEnv(name string) string {
	return os.Getenv(name)
}

// FileExists 检查文件是否存在
func FileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ChromeTimeToTime Chrome 时间戳 (1601-01-01 起 microseconds) 转 time.Time
func ChromeTimeToTime(us int64) time.Time {
	// 1601-01-01 到 1970-01-01 是 11644473600 秒
	return time.UnixMicro((us - 11644473600000000)).UTC()
}

// FirefoxTimeToTime Firefox 时间戳 (microseconds since epoch) 转 time.Time
func FirefoxTimeToTime(us int64) time.Time {
	return time.UnixMicro(us).UTC()
}

// ParseTime 通用时间解析, 失败返回 zero
func ParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ExpandPath 展开环境变量
func ExpandPath(p string) string {
	return os.ExpandEnv(p)
}

// CleanText 清理乱码, 保留可打印字符
func CleanText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			b.WriteRune(r)
		} else if r >= 0x80 && r <= 0xFF {
			b.WriteRune(r)
		} else if r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(' ')
		} else if r >= 0x4E00 && r <= 0x9FFF {
			// 中文
			b.WriteRune(r)
		}
	}
	res := b.String()
	if len(res) > 200 {
		res = res[:197] + "..."
	}
	return res
}

// GlobN 返回匹配的前 N 个文件
func GlobN(pattern string, n int) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches, nil
}

// SafeFileSize 安全获取文件大小
func SafeFileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// PrintSection 打印章节标题
func PrintSection(name string) {
	fmt.Println()
	fmt.Println("=====", name, "=====")
}

// FatalError 打印错误并退出
func FatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", args...)
	os.Exit(1)
}

// writeFileRaw 写文件 (通用)
func writeFileRaw(path string, b []byte) error {
	return os.WriteFile(path, b, 0644)
}
