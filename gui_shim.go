//go:build windows

package main

// 一些跨平台调用的 shim (避免在 gui.go 引入太多 os 包)

import "os"
import "time"

var timeNow = time.Now
var osGetenv = os.Getenv
var osGetpid = os.Getpid
