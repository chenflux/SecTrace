//go:build windows

// 解析器单元测试 (fixture 十六进制构造, 无需真实文件)

package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------- $I 回收站解析 ----------

// buildRecycleBinI 构造 $I 文件
// v2: [8头][8大小][8 FILETIME][8 流大小][路径UTF16]
func buildRecycleBinI(v uint64, size uint64, ft uint64, path string) []byte {
	var b bytes.Buffer
	b.Write(binary.LittleEndian.AppendUint64(nil, v))
	b.Write(binary.LittleEndian.AppendUint64(nil, size))
	b.Write(binary.LittleEndian.AppendUint64(nil, ft))
	if v == 2 {
		b.Write(binary.LittleEndian.AppendUint64(nil, size))
	}
	for _, c := range utf16.Encode([]rune(path)) {
		b.Write(binary.LittleEndian.AppendUint16(nil, c))
	}
	b.Write([]byte{0, 0})
	return b.Bytes()
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	f := t.TempDir() + "\\$I_TEST"
	if err := writeFileRaw(f, data); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseRecycleBinI_V2(t *testing.T) {
	ft := uint64(132600000000000000) // ~2021
	data := buildRecycleBinI(2, 1234, ft, `C:\Users\x\secret.txt`)
	p := writeTemp(t, data)
	item := parseRecycleBinI(p, `C:`)
	if item == nil {
		t.Fatal("v2 解析失败")
	}
	if item.Event != "已删除: secret.txt" {
		t.Errorf("Event = %q", item.Event)
	}
	if !strings.Contains(item.Detail, "1234 字节") || !strings.Contains(item.Detail, "v2") {
		t.Errorf("Detail = %q", item.Detail)
	}
	if item.Time.Year() != 2021 {
		t.Errorf("时间解析错误: %v", item.Time)
	}
}

func TestParseRecycleBinI_V1(t *testing.T) {
	ft := uint64(129000000000000000) // ~2009
	data := buildRecycleBinI(1, 100, ft, `C:\old.doc`)
	item := parseRecycleBinI(writeTemp(t, data), `D:`)
	if item == nil {
		t.Fatal("v1 解析失败")
	}
	if !strings.Contains(item.Detail, "v1") {
		t.Errorf("Detail = %q", item.Detail)
	}
}

func TestParseRecycleBinI_BadVersion(t *testing.T) {
	data := buildRecycleBinI(99, 1, 1, "x")
	if parseRecycleBinI(writeTemp(t, data), `C:`) != nil {
		t.Error("非法版本应返回 nil")
	}
}

// ---------- LNK 解析 ----------

// buildLNK 构造最小合法 LNK (HasLinkInfo + HasArguments)
func buildLNK(target string, args string) []byte {
	var b bytes.Buffer
	b.Write(binary.LittleEndian.AppendUint32(nil, 0x4C))                     // HeaderSize
	b.Write([]byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}) // CLSID
	flags := uint32(0x02 | 0x20 | 0x80) // HasLinkInfo | HasArguments | IsUnicode
	b.Write(binary.LittleEndian.AppendUint32(nil, flags))
	b.Write(make([]byte, 4))                                   // FileAttributes
	b.Write(binary.LittleEndian.AppendUint64(nil, 132600000000000100)) // CreateTime
	b.Write(binary.LittleEndian.AppendUint64(nil, 132600000000000200)) // AccessTime
	b.Write(binary.LittleEndian.AppendUint64(nil, 132600000000000300)) // WriteTime
	b.Write(binary.LittleEndian.AppendUint32(nil, 2048))       // FileSize
	b.Write(make([]byte, 20))                                  // IconIndex..Reserved (尾部补齐 → 头共 76, 实证 HeaderSize=0x4C)
	// LinkInfo: Size | HeaderSize(0x1C) | Flags(1=VolumeIDAndLocalBasePath)
	//          | VolumeIDOffset | LocalBasePathOffset | CNRL | CPS | [ANSI path]
	lbpOff := uint32(0x1C) // 头 28 字节后即路径
	liBody := new(bytes.Buffer)
	liBody.Write(binary.LittleEndian.AppendUint32(nil, 1))      // Flags
	liBody.Write(binary.LittleEndian.AppendUint32(nil, 0))      // VolumeIDOffset (无)
	liBody.Write(binary.LittleEndian.AppendUint32(nil, lbpOff)) // LocalBasePathOffset
	liBody.Write(binary.LittleEndian.AppendUint32(nil, 0))      // CommonNetworkRelativeLink
	liBody.Write(binary.LittleEndian.AppendUint32(nil, 0))      // CommonPathSuffix
	liBody.WriteString(target)
	liBody.WriteByte(0)
	li := new(bytes.Buffer)
	li.Write(binary.LittleEndian.AppendUint32(nil, uint32(0x1C+len(target)+1))) // LinkInfoSize (头28+路径+NUL)
	li.Write(binary.LittleEndian.AppendUint32(nil, 0x1C))                        // HeaderSize
	li.Write(liBody.Bytes())
	b.Write(li.Bytes())
	// StringData: Arguments (UTF16 长度前缀)
	b.Write(binary.LittleEndian.AppendUint16(nil, uint16(len([]rune(args)))))
	for _, c := range utf16.Encode([]rune(args)) {
		b.Write(binary.LittleEndian.AppendUint16(nil, c))
	}
	return b.Bytes()
}

func TestParseLNK(t *testing.T) {
	data := buildLNK(`C:\Windows\notepad.exe`, `-a file.txt`)
	p := parseLNKBytes(data)
	if p == nil {
		t.Fatal("LNK 解析失败")
	}
	if p.TargetPath != `C:\Windows\notepad.exe` {
		t.Errorf("Target = %q", p.TargetPath)
	}
	if p.Arguments != "-a file.txt" {
		t.Errorf("Args = %q", p.Arguments)
	}
	if p.FileSize != 2048 {
		t.Errorf("FileSize = %d", p.FileSize)
	}
	if p.WriteTime.IsZero() {
		t.Error("WriteTime 未解析")
	}
}

func TestParseLNK_BadMagic(t *testing.T) {
	if parseLNKBytes([]byte("NOTALNK1111")) != nil {
		t.Error("非 LNK 应返回 nil")
	}
}

// ---------- XPRESS Huffman 解压器 (回环: 解自造压缩流) ----------

func TestXpressRoundtripViaRtl(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	// 用 ntdll RtlCompressBuffer 造已知压缩流 (与生产取证同路径)
	plain := []byte("SCCA" + strings.Repeat("HELLO WORLD ", 64))
	comp := rtlCompressXpressHuff(plain) // helper 在下方 (测试辅助, 非 windows 也跳过)
	if comp == nil {
		t.Skip("RtlCompressBuffer 不可用")
	}
	dec, err := xpressHuffmanDecompress(comp, len(plain)+64)
	if err != nil && len(dec) == 0 {
		t.Fatalf("解压失败: %v", err)
	}
	// 契约: 输出 ≥ 目标长度 (尾部填充位可解出多余字节), 按 usize 截断
	if len(dec) >= len(plain) {
		dec = dec[:len(plain)]
	}
	if !bytes.Equal(dec, plain) {
		t.Errorf("回环不匹配: %d/%d 字节", len(dec), len(plain))
	}
}

// ---------- 事件 XML 解析 (单双引号 + 位置型 Data + SID 翻译) ----------

func TestParseEventXML_SingleQuote(t *testing.T) {
	xmlStr := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID Qualifiers='16384'>7045</EventID><Level>4</Level><TimeCreated SystemTime='2026-10-19T02:00:00.5000000Z'/></System><EventData><Data Name='param0'>EvilSvc</Data><Data Name='param1'>C:\temp\evil.exe</Data></EventData></Event>`
	eid, ts, level, f := parseEventXML(xmlStr)
	if eid != 7045 || level != 4 {
		t.Errorf("eid=%d level=%d", eid, level)
	}
	if ts.IsZero() || ts.Year() != 2026 {
		t.Errorf("时间: %v", ts)
	}
	if f["param0"] != "EvilSvc" || f["param1"] != `C:\temp\evil.exe` {
		t.Errorf("fields: %v", f)
	}
}

func TestParseEventXML_PositionalData(t *testing.T) {
	xmlStr := `<Event><System><EventID>6013</EventID></System><EventData><Data></Data><Data></Data><Data></Data><Data></Data><Data>183264</Data><Data>60</Data></EventData></Event>`
	_, _, _, f := parseEventXML(xmlStr)
	if f["data[4]"] != "183264" {
		t.Errorf("data[4] = %q (6013 布局依赖位置型数据)", f["data[4]"])
	}
}

func TestTranslateSIDs(t *testing.T) {
	in := "用户: S-1-5-18 | 其他: S-1-5-21-111-222-333-1001"
	out := translateSIDs(in)
	if !strings.Contains(out, "SYSTEM") {
		t.Errorf("常见 SID 未翻译: %q", out)
	}
	// 域 SID 无缓存时保留原文
	if !strings.Contains(out, "S-1-5-21-111-222-333-1001") {
		t.Errorf("域 SID 丢失: %q", out)
	}
}

// ---------- 自启动可疑启发式 ----------

func TestCheckAutoRunSuspicious(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{`C:\Windows\System32\svchost.exe`, false},
		{`C:\Users\x\AppData\Local\Temp\evil.exe`, true},   // Temp
		{`C:\Users\Public\payload.vbs`, true},              // Public + 脚本
		{`wscript.exe C:\x\run.ps1`, true},                 // 脚本扩展
		{`"C:\Program Files\App\app.exe" /bg`, false},
		{`C:\Downloads\setup.exe`, true},                   // Downloads
	}
	for _, c := range cases {
		got := checkAutoRunSuspicious(c.cmd) != ""
		if got != c.want {
			t.Errorf("checkAutoRunSuspicious(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// ---------- startupApproval 布局 (纯函数测试通过二进制) ----------

func TestBuildXHTree_CanonicalCodes(t *testing.T) {
	// 2 符号: sym0 len1, sym2 len1 → 树可解
	table := make([]byte, 256)
	table[0] = 0x01 // nibble[0]=1, nibble[1]=0
	table[1] = 0x01 // nibble[2]=1
	root := buildXHTree(table)
	if root == nil {
		t.Fatal("树构建失败")
	}
}

func TestFileTimeToTime(t *testing.T) {
	ft := uint64(132600000000000000)
	tt := fileTimeToTime(ft)
	if tt.Year() < 2010 || tt.Year() > 2021 {
		t.Errorf("FILETIME 转换: %v", tt)
	}
}

var _ = time.Now
