package main

import (
	"fmt"
	"os"
	"strings"
)

func exportTab(path string, headers []string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString(strings.Join(headers, "\t") + "\n")
	for _, r := range rows {
		// 替换 tab 避免破坏格式
		cleaned := make([]string, len(r))
		for i, c := range r {
			cleaned[i] = strings.ReplaceAll(c, "\t", " ")
		}
		f.WriteString(strings.Join(cleaned, "\t") + "\n")
	}
	return nil
}

var _ = fmt.Sprintf
