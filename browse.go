package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// BrowseEntry 单条浏览历史
type BrowseEntry struct {
	Browser   string
	URL       string
	Title     string
	VisitTime time.Time
}

// GetBrowserPaths 返回支持的浏览器数据库路径
func GetBrowserPaths() map[string][]string {
	paths := map[string][]string{}
	if runtime.GOOS != "windows" {
		return paths
	}
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")

	// Chrome
	for _, profile := range []string{"Default", "Profile 1", "Profile 2", "Profile 3"} {
		p := filepath.Join(local, "Google", "Chrome", "User Data", profile, "History")
		if FileExists(p) {
			paths["Chrome"] = append(paths["Chrome"], p)
		}
	}
	// Edge
	for _, profile := range []string{"Default", "Profile 1", "Profile 2"} {
		p := filepath.Join(local, "Microsoft", "Edge", "User Data", profile, "History")
		if FileExists(p) {
			paths["Edge"] = append(paths["Edge"], p)
		}
	}
	// Brave
	for _, profile := range []string{"Default", "Profile 1"} {
		p := filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data", profile, "History")
		if FileExists(p) {
			paths["Brave"] = append(paths["Brave"], p)
		}
	}
	// 360speed, QQ 浏览器等省略, 一般不在应急取证范围

	// Firefox
	ffBase := filepath.Join(roaming, "Mozilla", "Firefox", "Profiles")
	if FileExists(ffBase) {
		entries, _ := os.ReadDir(ffBase)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(ffBase, e.Name(), "places.sqlite")
			if FileExists(p) {
				paths["Firefox"] = append(paths["Firefox"], p)
			}
		}
	}
	return paths
}

// readChromeLikeHistory 读取 Chrome 内核浏览器历史
func readChromeLikeHistory(dbPath, browserName string, limit int, since time.Time) ([]BrowseEntry, error) {
	tmp, err := copyToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp+"?mode=ro&immutable=1")
	if err != nil {
		return nil, fmt.Errorf("打开 %s: %w", dbPath, err)
	}
	defer db.Close()

	// 尝试新版 schema (有 visits 表)
	query := `
		SELECT u.last_visit_time, u.title, u.url
		FROM urls u
		WHERE u.last_visit_time > 0
	`
	args := []interface{}{}
	if !since.IsZero() {
		cutoff := since.UnixMicro() + 11644473600000000
		query += " AND u.last_visit_time > ?"
		args = append(args, cutoff)
	}
	query += " ORDER BY u.last_visit_time DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		// 试 Firefox 模式
		return nil, fmt.Errorf("查询失败: %w", err)
	}
	defer rows.Close()

	var entries []BrowseEntry
	for rows.Next() {
		var ts int64
		var title, url string
		if err := rows.Scan(&ts, &title, &url); err != nil {
			continue
		}
		entries = append(entries, BrowseEntry{
			Browser:   browserName,
			URL:       url,
			Title:     CleanText(title),
			VisitTime: ChromeTimeToTime(ts),
		})
	}
	return entries, nil
}

// readFirefoxHistory 读取 Firefox 历史
func readFirefoxHistory(dbPath string, limit int, since time.Time) ([]BrowseEntry, error) {
	tmp, err := copyToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp+"?mode=ro&immutable=1")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
		SELECT h.visit_date, p.title, p.url
		FROM moz_historyvisits h
		JOIN moz_places p ON h.place_id = p.id
		WHERE h.visit_date > 0
	`
	args := []interface{}{}
	if !since.IsZero() {
		query += " AND h.visit_date > ?"
		args = append(args, since.UnixMicro())
	}
	query += " ORDER BY h.visit_date DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BrowseEntry
	for rows.Next() {
		var ts int64
		var title, url string
		if err := rows.Scan(&ts, &title, &url); err != nil {
			continue
		}
		entries = append(entries, BrowseEntry{
			Browser:   "Firefox",
			URL:       url,
			Title:     CleanText(title),
			VisitTime: FirefoxTimeToTime(ts),
		})
	}
	return entries, nil
}

// copyToTemp 复制 sqlite db 到临时文件 (因为浏览器 db 经常被锁)
func copyToTemp(src string) (string, error) {
	in, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "gosec-*.sqlite")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	return tmp.Name(), nil
}

// CollectBrowseHistory 收集所有浏览器历史
func CollectBrowseHistory(browsers []string, limit int, since time.Time) []BrowseEntry {
	paths := GetBrowserPaths()
	var all []BrowseEntry
	for browser, dbs := range paths {
		if len(browsers) > 0 && !contains(browsers, browser) {
			continue
		}
		for _, db := range dbs {
			var entries []BrowseEntry
			var err error
			if browser == "Firefox" {
				entries, err = readFirefoxHistory(db, limit, since)
			} else {
				entries, err = readChromeLikeHistory(db, browser, limit, since)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", browser, err)
				continue
			}
			all = append(all, entries...)
		}
	}
	// 按时间倒序
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[i].VisitTime.Before(all[j].VisitTime) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// PrintBrowseTable 打印浏览历史表格
func PrintBrowseTable(entries []BrowseEntry) {
	headers := []string{"时间", "浏览器", "标题", "URL"}
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			e.VisitTime.Local().Format("2006-01-02 15:04:05"),
			e.Browser,
			e.Title,
			e.URL,
		})
	}
	printTable(headers, rows)
	fmt.Printf("\n共 %d 条\n", len(entries))
}
