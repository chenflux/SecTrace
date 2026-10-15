//go:build windows

// RunMRU / TypedPaths / TypedURLs
// 用户最近运行的命令/输入的路径/输入的 URL
//
// 取证说明: 这些注册表值本身没有时间戳. 这里用键的 LastWriteTime
// 作为近似时间 (键最后被写入的时刻 = 最近一次添加条目的时刻),
// 并标记 Approx=true, 前端显示为 "≈时间" 以区别于精确时间戳.

package main

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// keyModTime 取注册表键的 LastWriteTime
func keyModTime(k registry.Key) (time.Time, bool) {
	stat, err := k.Stat()
	if err != nil {
		return time.Time{}, false
	}
	return stat.ModTime(), true
}

// readRunMRU HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
// 值名是字母 (a, b, c, ...), MRUList 值是顺序
func readRunMRU() []ActivityItem {
	var out []ActivityItem
	const p = `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
	k, err := registry.OpenKey(registry.CURRENT_USER, p, registry.READ)
	if err != nil {
		return out
	}
	defer k.Close()

	// 键 LastWriteTime = 最近一次运行命令写入的时刻 (近似)
	keyTime, hasTime := keyModTime(k)

	values, _ := k.ReadValueNames(50)
	// 按 MRUList 排序
	mruOrder := []string{}
	if list, _, err := k.GetStringValue("MRUList"); err == nil {
		for _, c := range list {
			mruOrder = append(mruOrder, string(c))
		}
	}
	// 找不到 MRUList 时, 按字母排序
	if len(mruOrder) == 0 {
		for _, n := range values {
			if n != "MRUList" {
				mruOrder = append(mruOrder, n)
			}
		}
	}

	for i, name := range mruOrder {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		out = append(out, ActivityItem{
			Time:   keyTime,
			Approx: hasTime, // 近似时间 (键最后写入)
			Type:   "RunMRU",
			Event:  fmt.Sprintf("运行命令 #%d: %s", i+1, strings.TrimRight(val, "\x01")),
			Detail: "完整值: " + val,
		})
	}
	return out
}

// readTypedPaths HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
// 值名 url1, url2... 内容是路径
func readTypedPaths() []ActivityItem {
	var out []ActivityItem
	const p = `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`
	k, err := registry.OpenKey(registry.CURRENT_USER, p, registry.READ)
	if err != nil {
		return out
	}
	defer k.Close()

	keyTime, hasTime := keyModTime(k)

	values, _ := k.ReadValueNames(100)
	// 按 url1, url2... 数字顺序
	for _, name := range values {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		out = append(out, ActivityItem{
			Time:   keyTime,
			Approx: hasTime,
			Type:   "TypedPaths",
			Event:  fmt.Sprintf("键入路径 [%s]: %s", name, val),
			Detail: val,
		})
	}
	return out
}

// readTypedURLs HKCU\Software\Microsoft\Internet Explorer\TypedURLs
func readTypedURLs() []ActivityItem {
	var out []ActivityItem
	const p = `Software\Microsoft\Internet Explorer\TypedURLs`
	k, err := registry.OpenKey(registry.CURRENT_USER, p, registry.READ)
	if err != nil {
		return out
	}
	defer k.Close()

	keyTime, hasTime := keyModTime(k)

	values, _ := k.ReadValueNames(100)
	for _, name := range values {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}
		out = append(out, ActivityItem{
			Time:   keyTime,
			Approx: hasTime,
			Type:   "TypedURLs",
			Event:  fmt.Sprintf("IE键入URL [%s]: %s", name, val),
			Detail: val,
		})
	}
	return out
}
