//go:build windows

// 网络连接/断开记录
// 来源: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
// 每个 GUID 子键: ProfileName, Description, NameType, Category, Managed,
//                 DateCreated (FILETIME), LastConnected (FILETIME)
//
// NameType:  6=有线, 23=无线, 71=移动宽带
// Category:  0=公用, 1=专用, 2=域

package main

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func networkNameTypeLabel(t uint64) string {
	switch t {
	case 6:
		return "有线"
	case 23:
		return "无线"
	case 71:
		return "移动宽带"
	default:
		return fmt.Sprintf("类型=%d", t)
	}
}

func networkCategoryLabel(c uint64) string {
	switch c {
	case 0:
		return "公用网络"
	case 1:
		return "专用网络"
	case 2:
		return "域网络"
	default:
		return fmt.Sprintf("类别=%d", c)
	}
}

// readNetworkProfiles 读所有网络配置
func readNetworkProfiles() []ActivityItem {
	var out []ActivityItem
	const base = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return out
	}
	defer k.Close()

	guids, _ := k.ReadSubKeyNames(100)
	for _, guid := range guids {
		pk, err := registry.OpenKey(k, guid, registry.READ)
		if err != nil {
			continue
		}
		profileName, _, _ := pk.GetStringValue("ProfileName")
		description, _, _ := pk.GetStringValue("Description")
		managed, _, _ := pk.GetIntegerValue("Managed")
		nameType, _, _ := pk.GetIntegerValue("NameType")
		category, _, _ := pk.GetIntegerValue("Category")

		typeLabel := networkNameTypeLabel(nameType)
		catLabel := networkCategoryLabel(category)
		managedStr := "非托管"
		if managed == 1 {
			managedStr = "域托管"
		}

		// DateCreated: 8 字节 FILETIME
		var createdTime time.Time
		if data, _, err := pk.GetBinaryValue("DateCreated"); err == nil && len(data) >= 8 {
			ft := binary.LittleEndian.Uint64(data[0:8])
			createdTime = fileTimeToTime(ft)
		}
		// LastConnected: 8 字节 FILETIME
		var lastConnTime time.Time
		if data, _, err := pk.GetBinaryValue("LastConnected"); err == nil && len(data) >= 8 {
			ft := binary.LittleEndian.Uint64(data[0:8])
			lastConnTime = fileTimeToTime(ft)
		}
		pk.Close()

		// 两条记录: 已创建 + 最后连接
		if !createdTime.IsZero() {
			out = append(out, ActivityItem{
				Time:   createdTime,
				Approx: false,
				Type:   "网络",
				Event:  fmt.Sprintf("创建网络配置: %s", profileName),
				Detail: fmt.Sprintf("类型: %s | %s | %s | 描述: %s", typeLabel, catLabel, managedStr, description),
			})
		}
		if !lastConnTime.IsZero() {
			out = append(out, ActivityItem{
				Time:   lastConnTime,
				Approx: false,
				Type:   "网络",
				Event:  fmt.Sprintf("最后连接: %s", profileName),
				Detail: fmt.Sprintf("类型: %s | %s | %s | 描述: %s | GUID: %s", typeLabel, catLabel, managedStr, description, guid),
			})
		}
	}
	return out
}

// readWirelessSignatures 读无线网络签名 (SSID/BSSID 信息)
// HKLM\...\NetworkList\Signatures\01\{sig}
func readWirelessSignatures() []ActivityItem {
	var out []ActivityItem
	const base = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return out
	}
	defer k.Close()
	// 跳过 00/01 子键描述
	_, _ = k.Stat()

	sigGroups, _ := k.ReadSubKeyNames(10)
	for _, group := range sigGroups {
		// group 通常是 "01" (Unmanaged) 或 "0F" (Managed)
		gk, err := registry.OpenKey(k, group, registry.READ)
		if err != nil {
			continue
		}
		sigs, _ := gk.ReadSubKeyNames(50)
		for _, sig := range sigs {
			sk, err := registry.OpenKey(gk, sig, registry.READ)
			if err != nil {
				continue
			}
			ssidStr, _, _ := sk.GetStringValue("SSID")
			ssidHex, _, _ := sk.GetStringValue("ProfileGuid")
			// 关键: 默认网关 MAC = 路由器 MAC, BSSID 列表 = 连接过的 AP
			defaultGatewayMac, _, _ := sk.GetStringValue("DefaultGatewayMac")
			bssidList, _, _ := sk.GetBinaryValue("LocationOfCellList")
			firstSeen, _, _ := sk.GetBinaryValue("FirstNetwork") // 8 字节 FILETIME

			var firstSeenTime time.Time
			if len(firstSeen) >= 8 {
				ft := binary.LittleEndian.Uint64(firstSeen[0:8])
				firstSeenTime = fileTimeToTime(ft)
			}

			if ssidStr == "" && defaultGatewayMac == "" && len(bssidList) == 0 {
				sk.Close()
				continue
			}
			var bssidStr string
			if len(bssidList) >= 6 {
				bssidStr = formatMac(bssidList[:6])
			}
			detail := fmt.Sprintf("SSID: %s | 网关MAC: %s | BSSID: %s",
				ssidHex, defaultGatewayMac, bssidStr)
			out = append(out, ActivityItem{
				Time:   firstSeenTime,
				Approx: false,
				Type:   "无线",
				Event:  fmt.Sprintf("发现无线网络: %s", ssidHex),
				Detail: detail,
			})
			sk.Close()
		}
		gk.Close()
	}
	return out
}

func formatMac(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

// 抑制 unused 警告
var _ = strings.ToLower
var _ = filepath.Base
