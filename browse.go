package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

// chromiumVendor 各 Chromium 系浏览器的 User Data 目录与名称
var chromiumVendors = []struct {
	name    string
	dataDir string // 相对 %LOCALAPPDATA%
}{
	{"Chrome", filepath.Join("Google", "Chrome", "User Data")},
	{"Edge", filepath.Join("Microsoft", "Edge", "User Data")},
	{"Brave", filepath.Join("BraveSoftware", "Brave-Browser", "User Data")},
	{"Vivaldi", filepath.Join("Vivaldi", "User Data")},
	{"Opera", filepath.Join("Opera Software", "Opera Stable")},
}

// localStateProfiles 解析 User Data\Local State JSON, 返回全部 profile 目录名
// ("Default", "Profile 1", 自命名 Profile 等); 解析失败回退常用列表
func localStateProfiles(userDataDir string) []string {
	fallback := []string{"Default", "Profile 1", "Profile 2", "Profile 3"}
	data, err := os.ReadFile(filepath.Join(userDataDir, "Local State"))
	if err != nil {
		return fallback
	}
	var ls struct {
		Profile struct {
			InfoCache map[string]struct {
				Name string `json:"name"`
			} `json:"info_cache"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(data, &ls); err != nil || len(ls.Profile.InfoCache) == 0 {
		return fallback
	}
	var out []string
	for dir := range ls.Profile.InfoCache {
		out = append(out, dir)
	}
	sort.Strings(out) // Default 在前, Profile N 递增
	return out
}

// GetBrowserPaths 返回支持的浏览器数据库路径
func GetBrowserPaths() map[string][]string {
	paths := map[string][]string{}
	if runtime.GOOS != "windows" {
		return paths
	}
	local := os.Getenv("LOCALAPPDATA")
	roaming := os.Getenv("APPDATA")

	// Chromium 系: 按 Local State 枚举全部 Profile
	for _, v := range chromiumVendors {
		userData := filepath.Join(local, v.dataDir)
		if !FileExists(userData) {
			continue
		}
		for _, profile := range localStateProfiles(userData) {
			p := filepath.Join(userData, profile, "History")
			if FileExists(p) {
				paths[v.name] = append(paths[v.name], p)
			}
		}
	}

	// Firefox: 枚举 Profiles 目录
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

// readChromeLikeHistory 读取 Chromium 系浏览器历史
// JOIN visits 表: 同一 URL 的每次访问都独立成行 (含转 guid 映射来源)
func readChromeLikeHistory(dbPath, browserName string, limit int, since time.Time) ([]BrowseEntry, error) {
	tmp, err := copySQLiteSafe(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, fmt.Errorf("打开 %s: %w", dbPath, err)
	}
	defer db.Close()

	query := `
		SELECT v.visit_time, u.title, u.url
		FROM visits v JOIN urls u ON v.url = u.id
		WHERE v.visit_time > 0
	`
	args := []interface{}{}
	if !since.IsZero() {
		cutoff := since.UnixMicro() + 11644473600000000
		query += " AND v.visit_time > ?"
		args = append(args, cutoff)
	}
	query += " ORDER BY v.visit_time DESC"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		// 旧版/异常 schema 回退到 urls 表
		return readChromeLikeHistoryLegacy(db, dbPath, browserName, limit, since)
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

// readChromeLikeHistoryLegacy 回退: 只用 urls.last_visit_time (每次访问折叠为一条)
func readChromeLikeHistoryLegacy(db *sql.DB, dbPath, browserName string, limit int, since time.Time) ([]BrowseEntry, error) {
	query := `SELECT u.last_visit_time, u.title, u.url FROM urls u WHERE u.last_visit_time > 0`
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
	tmp, err := copySQLiteSafe(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, fmt.Errorf("打开 %s: %w", dbPath, err)
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
			Browser:   "Firefox",
			URL:       url,
			Title:     CleanText(title),
			VisitTime: FirefoxTimeToTime(ts),
		})
	}
	return entries, nil
}

// copySQLiteSafe 复制 SQLite 库到临时文件
// 关键: 浏览器运行中时最近记录在 WAL 里未刷盘, 必须连同 -wal/-shm 一起复制,
// 否则丢最后几小时的访问记录; 无 WAL 时只复制主库
func copySQLiteSafe(src string) (string, error) {
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
	// 连带 WAL/SHM (存在才复制, 同名前缀)
	for _, suffix := range []string{"-wal", "-shm"} {
		side, err := os.ReadFile(src + suffix)
		if err != nil {
			continue // 大多数情况没有 WAL
		}
		_ = os.WriteFile(tmp.Name()+suffix, side, 0644)
	}
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
	sort.SliceStable(all, func(i, j int) bool { return all[i].VisitTime.After(all[j].VisitTime) })
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
