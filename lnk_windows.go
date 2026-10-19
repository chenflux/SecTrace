//go:build windows

// LNK (Shell Shortcut) 原生二进制解析器 — MS-SHLLINK 规范
// 替代 PowerShell COM 方案: 0 次 fork, 且能拿到 COM 拿不到的字段
// (目标三时间戳 / 文件大小 / 卷序列号)

package main

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// lnkParsed LNK 解析结果
type lnkParsed struct {
	TargetPath  string
	Arguments   string
	WorkingDir  string
	Name        string
	IconPath    string
	CreateTime  time.Time // 目标文件创建时间 (链接创建时刻的快照)
	AccessTime  time.Time
	WriteTime   time.Time
	FileSize    uint32
	VolumeSN    uint32 // 卷序列号 (识别 U 盘/网络盘来源的线索)
}

// LinkFlags 位定义 (MS-SHLLINK 2.1.1)
const (
	lnkHasIDList    = 0x01
	lnkHasLinkInfo  = 0x02
	lnkHasName      = 0x04
	lnkHasRelPath   = 0x08
	lnkHasWorkDir   = 0x10
	lnkHasArguments = 0x20
	lnkHasIcon      = 0x40
	lnkIsUnicode    = 0x80
)

// parseLNKBytes 解析 LNK 二进制; 非 LNK 返回 nil
func parseLNKBytes(data []byte) *lnkParsed {
	if len(data) < 76 {
		return nil
	}
	// ShellLinkHeader: HeaderSize=0x4C + LinkCLSID(16B)
	if binary.LittleEndian.Uint32(data[0:4]) != 0x4C {
		return nil
	}
	if !isLinkCLSID(data[4:20]) {
		return nil
	}
	flags := binary.LittleEndian.Uint32(data[0x14:0x18])

	p := &lnkParsed{
		CreateTime: fileTimeToTime(binary.LittleEndian.Uint64(data[0x1C:0x24])),
		AccessTime: fileTimeToTime(binary.LittleEndian.Uint64(data[0x24:0x2C])),
		WriteTime:  fileTimeToTime(binary.LittleEndian.Uint64(data[0x2C:0x34])),
		FileSize:   binary.LittleEndian.Uint32(data[0x34:0x38]),
	}

	off := 76
	// LinkTargetIDList: u16 size + 数据, 直接跳过
	if flags&lnkHasIDList != 0 {
		if off+2 > len(data) {
			return nil
		}
		idlSize := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2 + idlSize
		if off > len(data) {
			return nil
		}
	}
	// LinkInfo
	if flags&lnkHasLinkInfo != 0 && off+28 <= len(data) {
		liSize := int(binary.LittleEndian.Uint32(data[off : off+4]))
		liFlags := binary.LittleEndian.Uint32(data[off+8 : off+12])
		if liSize > 0 && off+liSize <= len(data) {
			li := data[off : off+liSize]
			// ANSI LocalBasePath (flag bit0 = VolumeIDAndLocalBasePath)
			if liFlags&1 != 0 {
				if o := int(binary.LittleEndian.Uint32(li[0x10:0x14])); o > 0 && o < len(li) {
					p.TargetPath = readANSINullTerm(li[o:])
				}
			}
			// Unicode LocalBasePath (flag bit2, 偏移在 0x1C)
			if liFlags&4 != 0 && len(li) > 0x1C {
				if o := int(binary.LittleEndian.Uint32(li[0x1C:0x20])); o > 0 && o < len(li) {
					p.TargetPath = utf16NullTermToString(li[o:])
				}
			}
			// VolumeID: 0x00 Size | 0x04 DriveType | 0x08 DriveSerialNumber
			if liFlags&1 != 0 {
				if vo := int(binary.LittleEndian.Uint32(li[0x0C:0x10])); vo > 0 && vo+12 <= len(li) {
					p.VolumeSN = binary.LittleEndian.Uint32(li[vo+8 : vo+12])
				}
			}
		}
		if off+4 <= len(data) {
			off += int(binary.LittleEndian.Uint32(data[off : off+4]))
		}
	}
	// StringData: 按 flag 顺序 Name/RelPath/WorkDir/Arguments/Icon
	// 每项: u16 字符数 + UTF-16 数据 (IsUnicode 实际恒置位)
	unicode := flags&lnkIsUnicode != 0
	strs := []*string{&p.Name, new(string), &p.WorkingDir, &p.Arguments, &p.IconPath}
	bits := []uint32{lnkHasName, lnkHasRelPath, lnkHasWorkDir, lnkHasArguments, lnkHasIcon}
	for i, bit := range bits {
		if flags&bit == 0 {
			continue
		}
		if off+2 > len(data) {
			break
		}
		n := int(binary.LittleEndian.Uint16(data[off : off+2]))
		off += 2
		if off+n*2 > len(data) {
			break
		}
		b := data[off : off+n*2]
		off += n * 2
		if unicode {
			u := make([]uint16, n)
			for k := 0; k < n; k++ {
				u[k] = binary.LittleEndian.Uint16(b[k*2 : k*2+2])
			}
			*strs[i] = string(utf16.Decode(u))
		} else {
			*strs[i] = string(b)
		}
	}
	return p
}

func isLinkCLSID(b []byte) bool {
	want := []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
	for i, v := range want {
		if b[i] != v {
			return false
		}
	}
	return true
}

func readANSINullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func utf16NullTermToString(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}
