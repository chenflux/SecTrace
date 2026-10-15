//go:build windows

package main

import (
	_ "embed"
	"strings"
)

//go:embed assets/index.html
var indexHTMLRaw string

// 替换 embed 文件里的 go:embed 行
var indexHTML = strings.ReplaceAll(indexHTMLRaw, "{{VERSION}}", version)
