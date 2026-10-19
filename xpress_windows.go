//go:build windows

// XPRESS-Huffman (MS-XCA / LZXPRESS) 解压器 — Go 移植
// 参考实现: dissect.util.compression.lzxpress_huffman (已在本机
// 真实 Prefetch 上验证解压正确)
//
// 格式: 循环块 { 256B 哈夫曼表(512 nibble 码长) + 位流 }
//   - 位流: 32 位 MSB-first 掩码, 按 LE u16 补充
//   - 符号 < 256: 字面量
//   - 符号 >= 256: s = sym-256; len = (s & 0xF); n = s >> 4
//       offset = (1<<n) + peek(n)
//       len == 15 时: len = 下 1 字节 + 15; 若 == 270 再读 u16
//       len += 3; 消耗 n 位 offset 附加位

package main

import (
	"encoding/binary"
	"errors"
	"io"
)

type xhReader struct {
	src  []byte
	pos  int
	mask uint32
	bits int
}

func (r *xhReader) u16() uint16 {
	if r.pos+2 > len(r.src) {
		r.pos += 2
		return 0
	}
	v := binary.LittleEndian.Uint16(r.src[r.pos:])
	r.pos += 2
	return v
}

func (r *xhReader) byte1() byte {
	if r.pos >= len(r.src) {
		r.pos++
		return 0
	}
	v := r.src[r.pos]
	r.pos++
	return v
}

func (r *xhReader) init() {
	r.mask = uint32(r.u16())<<16 | uint32(r.u16())
	r.bits = 32
}

func (r *xhReader) lookup(n int) uint32 {
	if n == 0 {
		return 0
	}
	return r.mask >> (32 - uint(n))
}

func (r *xhReader) skip(n int) {
	r.mask = (r.mask << uint(n)) & 0xFFFFFFFF
	r.bits -= n
	if r.bits < 16 {
		r.mask |= uint32(r.u16()) << uint(16-r.bits)
		r.bits += 16
	}
}

// xhNode 哈夫曼树节点
type xhNode struct {
	children [2]*xhNode
	symbol   int
	isLeaf   bool
}

// buildXHTree 由 256 字节码长表构建解码树 (512 符号, 规范码)
func buildXHTree(table []byte) *xhNode {
	type sym struct {
		length int
		symbol int
	}
	var syms []sym
	for i, c := range table {
		if c&0x0F > 0 {
			syms = append(syms, sym{int(c & 0x0F), i * 2})
		}
		if (c>>4)&0x0F > 0 {
			syms = append(syms, sym{int((c >> 4) & 0x0F), i*2 + 1})
		}
	}
	// 按 (长度, 符号) 排序
	for i := 0; i < len(syms); i++ {
		for j := i + 1; j < len(syms); j++ {
			if syms[j].length < syms[i].length ||
				(syms[j].length == syms[i].length && syms[j].symbol < syms[i].symbol) {
				syms[i], syms[j] = syms[j], syms[i]
			}
		}
	}
	// 规范码 → 树
	root := &xhNode{}
	code := 0
	prevLen := 0
	for _, s := range syms {
		code <<= uint(s.length - prevLen)
		node := root
		for b := s.length - 1; b >= 0; b-- {
			bit := (code >> uint(b)) & 1
			if node.children[bit] == nil {
				node.children[bit] = &xhNode{}
			}
			node = node.children[bit]
		}
		node.isLeaf = true
		node.symbol = s.symbol
		code++
		prevLen = s.length
	}
	return root
}

func (r *xhReader) decodeSym(root *xhNode) int {
	node := root
	for !node.isLeaf {
		bit := r.lookup(1)
		r.skip(1)
		if bit == 0 {
			node = node.children[0]
		} else {
			node = node.children[1]
		}
		if node == nil {
			return -1
		}
	}
	return node.symbol
}

// xpressHuffmanDecompress 解压完整流 (自动处理 64KB 分块)
func xpressHuffmanDecompress(src []byte, maxOut int) ([]byte, error) {
	if maxOut <= 0 {
		maxOut = 64 << 20
	}
	r := &xhReader{src: src}
	out := make([]byte, 0, 1<<16)
	start := 0
	for start < len(src) {
		if r.pos+256 > len(src) {
			break
		}
		if r.pos+256 > len(src) {
			break // 剩余不足一张表
		}
		table := src[r.pos : r.pos+256]
		r.pos += 256
		root := buildXHTree(table)
		r.init()
		chunk := 0
		for chunk < 65536 && r.pos < len(src) {
			sym := r.decodeSym(root)
			if sym < 0 {
				return out, nil
			}
			if sym < 256 {
				out = append(out, byte(sym))
				chunk++
			} else {
				s := sym - 256
				length := s & 0x0F
				n := s >> 4
				offset := (1 << uint(n)) + int(r.lookup(n))
				if length == 15 {
					length = int(r.byte1()) + 15
					if length == 270 {
						length = int(r.u16())
					}
				}
				r.skip(n)
				length += 3
				if offset <= 0 || offset > len(out) || length < 3 {
					return out, errors.New("xpress: 非法匹配")
				}
				totalLen := length
				for length > 0 {
					m := length
					if m > offset {
						m = offset
					}
					out = append(out, out[len(out)-offset:len(out)-offset+m]...)
					length -= m
				}
				chunk += totalLen
			}
			if len(out) >= maxOut {
				return out[:maxOut], nil
			}
		}
		start = r.pos
	}
	return out, nil
}

var _ = io.EOF
