//go:build windows

package main

// USB 设备使用记录 - 从注册表读取

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// collectUSBToRows 直接从注册表读 USB 并格式化为行
func collectUSBToRows() [][]string {
	rows := [][]string{}
	// USBSTOR: SYSTEM\CurrentControlSet\Enum\USBSTOR
	base := `SYSTEM\CurrentControlSet\Enum\USBSTOR`
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return rows
	}
	defer root.Close()

	subNames, _ := root.ReadSubKeyNames(100)
	for _, devName := range subNames {
		vid, pid := parseVidPid(devName)
		devKey, err := registry.OpenKey(root, devName, registry.READ)
		if err != nil {
			continue
		}
		// 每个 dev 下是 serial
		serials, _ := devKey.ReadSubKeyNames(10)
		devKey.Close()
		for _, serial := range serials {
			fullPath := base + `\` + devName + `\` + serial
			row := readUSBDeviceRow(fullPath, vid, pid, serial)
			if len(row) > 0 {
				rows = append(rows, row)
			}
		}
	}
	return rows
}

func parseVidPid(devName string) (vid, pid string) {
	// devName: "Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP"
	parts := splitRaw(devName, '&')
	for _, p := range parts {
		if len(p) > 4 && p[:4] == "Ven_" {
			vid = p[4:]
		} else if len(p) > 5 && p[:5] == "Prod_" {
			pid = p[5:]
		}
	}
	return
}

func splitRaw(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func readUSBDeviceRow(path, vid, pid, serial string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return nil
	}
	defer k.Close()

	friendly, _, _ := k.GetStringValue("FriendlyName")
	mfg, _, _ := k.GetStringValue("Mfg")
	_ = mfg

	// Properties 找最近时间
	// 路径: SYSTEM\CurrentControlSet\Enum\USBSTOR\Dev\Serial\Properties\{a8b865dd-2e3d-4094-ad97-e593a70c75d6}\0064
	propsKey := path + `\Properties\{a8b865dd-2e3d-4094-ad97-e593a70c75d6}`
	pk, err := registry.OpenKey(registry.LOCAL_MACHINE, propsKey, registry.READ)
	lastArrival := ""
	if err == nil {
		// 尝试 Last Arrival Date (REG_BINARY, 8 字节 FILETIME)
		// 实际位置在 \Device Parameters 下
		pk.Close()
		dpKey := path + `\Device Parameters`
		dp, err := registry.OpenKey(registry.LOCAL_MACHINE, dpKey, registry.READ)
		if err == nil {
			data, _, err2 := dp.GetBinaryValue("LastArrivalDate")
			if err2 == nil && len(data) >= 8 {
				ft := uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
					uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
				if ft > 0 {
					t := fileTimeToTime(ft)
					lastArrival = t.Format("2006-01-02 15:04:05")
				}
			}
			dp.Close()
		}
	}

	return []string{vid, pid, serial, friendly, lastArrival}
}

// getDesktopPath 获取桌面路径
func getDesktopPath() string {
	// 优先 USERPROFILE\Desktop
	if p := os.Getenv("USERPROFILE"); p != "" {
		return p + `\Desktop`
	}
	// 退而求其次: 当前目录
	wd, _ := syscall.Getwd()
	if wd != "" {
		return wd
	}
	return "."
}

// writeFile 写文件
func writeFile(path, content string) error {
	return writeBytes(path, []byte(content))
}

func writeBytes(path string, b []byte) error {
	return writeFileRaw(path, b)
}
