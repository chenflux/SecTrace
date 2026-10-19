//go:build windows

// UI 状态持久化: 列宽等界面配置落盘 %APPDATA%\SecTrace\ui.json
// (WebView2 about:blank origin 的 localStorage 跨启动不可靠, 走 Go 侧)

package main

import (
	"os"
	"path/filepath"
)

func uiStatePath() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return "sectrace_ui.json"
	}
	dir := filepath.Join(appData, "SecTrace")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "ui.json")
}

func readUIStateFile() string {
	data, err := os.ReadFile(uiStatePath())
	if err != nil {
		return "{}"
	}
	return string(data)
}

func saveUIStateFile(jsonStr string) {
	_ = os.WriteFile(uiStatePath(), []byte(jsonStr), 0644)
}
