//go:build windows

// 测试辅助: ntdll 压缩 (仅测试用)

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// rtlCompressXpressHuff 用 ntdll 造 XPRESS_HUFF 压缩流 (回环测试用)
func rtlCompressXpressHuff(plain []byte) []byte {
	ntdll := windows.NewLazySystemDLL("ntdll")
	comp := ntdll.NewProc("RtlCompressBuffer")
	wsSize := ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	var cws, dws uint32
	r, _, _ := wsSize.Call(4, uintptr(unsafe.Pointer(&cws)), uintptr(unsafe.Pointer(&dws)))
	if r != 0 {
		return nil
	}
	ws := make([]byte, cws)
	dst := make([]byte, len(plain)+65536)
	var final uint32
	src := make([]byte, len(plain))
	copy(src, plain)
	r2, _, _ := comp.Call(
		4,
		uintptr(unsafe.Pointer(&src[0])), uintptr(len(src)),
		uintptr(unsafe.Pointer(&dst[0])), uintptr(len(dst)),
		0, uintptr(unsafe.Pointer(&final)),
		uintptr(unsafe.Pointer(&ws[0])))
	if r2 != 0 {
		return nil
	}
	return dst[:final]
}
