// gosectrace - Go 版活动痕迹 + 浏览历史查看器
// 集成 browsinghistoryview + lastActivityView 功能
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

type Format int

const (
	FormatText Format = iota
	FormatCSV
	FormatJSON
)

func parseFormat(s string) Format {
	switch strings.ToLower(s) {
	case "csv":
		return FormatCSV
	case "json":
		return FormatJSON
	default:
		return FormatText
	}
}

// PrintRows 表格打印, 自动计算列宽
func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Println("(无数据)")
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			w := utf8.RuneCountInString(c)
			if w > widths[i] {
				widths[i] = w
			}
		}
	}
	// 表头
	for i, h := range headers {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Print(padRune(h, widths[i]))
	}
	fmt.Println()
	for _, w := range widths {
		if w > 0 {
			fmt.Print(strings.Repeat("-", w+2))
		}
	}
	fmt.Println()
	// 数据
	for _, r := range rows {
		for i, c := range r {
			if i > 0 {
				fmt.Print("  ")
			}
			// URL/详情列截断过长的内容
			s := c
			if widths[i] > 80 && utf8.RuneCountInString(s) > 80 {
				runes := []rune(s)
				s = string(runes[:77]) + "..."
			}
			fmt.Print(padRune(s, widths[i]))
		}
		fmt.Println()
	}
}

func padRune(s string, w int) string {
	n := utf8.RuneCountInString(s)
	if n >= w {
		return s
	}
	return s + strings.Repeat(" ", w-n)
}

// ExportCSV 导出为 CSV
func exportCSV(path string, headers []string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// 写入 UTF-8 BOM 方便 Excel 打开
	f.Write([]byte{0xEF, 0xBB, 0xBF})
	w := csv.NewWriter(f)
	w.Write(headers)
	for _, r := range rows {
		w.Write(r)
	}
	w.Flush()
	return w.Error()
}

// ExportJSON 导出为 JSON 数组
func exportJSON(path string, rows [][]string, headers []string) error {
	type Item map[string]string
	out := make([]Item, 0, len(rows))
	for _, r := range rows {
		item := make(Item, len(headers))
		for i, h := range headers {
			item[h] = r[i]
		}
		out = append(out, item)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
