// app_locate.go 负责定位 Ant Browser 的开发版/正式版目录、解析最小配置（config.yaml），
// 以只读快照方式查询 data/app.db 中的实例列表，以及按需创建最小空壳实例条目。
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

// minimalAppConfig 仅映射 Ant Browser config.yaml 中定位数据库、实例目录与兜底代理所需的最小字段，
// 避免与主项目配置结构耦合。
type minimalAppConfig struct {
	Database struct {
		SQLite struct {
			Path string `yaml:"path"`
		} `yaml:"sqlite"`
	} `yaml:"database"`
	Browser struct {
		UserDataRoot string `yaml:"user_data_root"`
		Proxies      []struct {
			ProxyID         string `yaml:"proxy_id"`
			ProxyName       string `yaml:"proxy_name"`
			ProxyConfig     string `yaml:"proxy_config"`
			PreferredKernel string `yaml:"preferred_kernel"`
			DNSServers      string `yaml:"dns_servers"`
			GroupName       string `yaml:"group_name"`
		} `yaml:"proxies"`
	} `yaml:"browser"`
}

// resolveAppInstallation 解析用户传入或自动发现的目录，兼容 ~ 展开、macOS .app 重定向及误传 data 子目录的容错。
func resolveAppInstallation(appRoot string) (*AppInstallation, error) {
	trimmed := strings.TrimSpace(appRoot)
	if trimmed == "" {
		return nil, fmt.Errorf("应用根目录不能为空")
	}
	if strings.HasPrefix(trimmed, "~/") || trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if trimmed == "~" {
				trimmed = home
			} else {
				trimmed = filepath.Join(home, trimmed[2:])
			}
		}
	}
	absRoot, err := filepath.Abs(trimmed)
	if err != nil {
		return nil, fmt.Errorf("解析目录路径失败: %w", err)
	}
	absRoot = normalizePlatformAppRoot(absRoot)
	// 容错：若用户不小心传了 <appRoot>/data 目录，则自动回到上一级
	if strings.EqualFold(filepath.Base(absRoot), "data") {
		parent := filepath.Dir(absRoot)
		if fileExists(filepath.Join(absRoot, "app.db")) &&
			(fileExists(filepath.Join(parent, "config.yaml")) ||
				fileExists(filepath.Join(parent, "ant-chrome.exe")) ||
				fileExists(filepath.Join(parent, "ant-chrome")) ||
				fileExists(filepath.Join(parent, "wails.json"))) {
			absRoot = parent
		}
	}

	info, err := os.Stat(absRoot)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("目录不存在或不是有效目录: %s", absRoot)
	}

	cfgPath := filepath.Join(absRoot, "config.yaml")
	dbRel := "data/app.db"
	userDataRel := "data"
	if raw, readErr := os.ReadFile(cfgPath); readErr == nil {
		var cfg minimalAppConfig
		if yamlErr := yaml.Unmarshal(raw, &cfg); yamlErr == nil {
			if p := strings.TrimSpace(cfg.Database.SQLite.Path); p != "" {
				dbRel = p
			}
			if r := strings.TrimSpace(cfg.Browser.UserDataRoot); r != "" {
				userDataRel = r
			}
		}
	}

	dbPath := resolveRelative(absRoot, dbRel)
	userDataRoot := resolveRelative(absRoot, userDataRel)
	mode := detectAppMode(absRoot)

	inst := &AppInstallation{
		AppRoot:      absRoot,
		Mode:         mode,
		ConfigPath:   cfgPath,
		DBPath:       dbPath,
		UserDataRoot: userDataRoot,
		HasAppDB:     fileExists(dbPath),
	}
	if inst.HasAppDB {
		active, deleted, err := countProfilesInDB(dbPath)
		if err == nil {
			inst.ActiveCount = active
			inst.DeletedCount = deleted
		}
	}
	return inst, nil
}

// detectAppMode 判断目录是源码开发模式（dev.bat / wails.json）还是正式发布版。
func detectAppMode(appRoot string) string {
	if fileExists(filepath.Join(appRoot, "wails.json")) || fileExists(filepath.Join(appRoot, "bat", "dev.bat")) {
		return "dev"
	}
	return "release"
}

// discoverAppInstallations 扫描当前工作目录、工具周边目录及平台标准安装位置，返回去重后的 Ant Browser 候选列表。
func discoverAppInstallations() []AppInstallation {
	type candidate struct {
		path  string
		label string
	}
	var rawCandidates []candidate

	if cwd, err := os.Getwd(); err == nil {
		rawCandidates = append(rawCandidates,
			candidate{path: cwd, label: "当前目录"},
			candidate{path: filepath.Dir(cwd), label: "上级目录"},
			candidate{path: filepath.Dir(filepath.Dir(cwd)), label: "仓库根目录"},
		)
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		rawCandidates = append(rawCandidates,
			candidate{path: exeDir, label: "工具所在目录"},
			candidate{path: filepath.Dir(exeDir), label: "工具上级目录"},
			candidate{path: filepath.Dir(filepath.Dir(exeDir)), label: "项目根目录"},
		)
	}

	// Windows 正式版默认安装位置 & 注册表安装记录
	for _, item := range discoverPlatformReleaseCandidates() {
		rawCandidates = append(rawCandidates, candidate{path: item.path, label: item.label})
	}

	seen := make(map[string]struct{})
	var results []AppInstallation
	for _, c := range rawCandidates {
		if strings.TrimSpace(c.path) == "" {
			continue
		}
		absPath, err := filepath.Abs(c.path)
		if err != nil {
			continue
		}
		key := strings.ToLower(filepath.Clean(absPath))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		if !looksLikeAntBrowserRoot(absPath) {
			continue
		}
		inst, err := resolveAppInstallation(absPath)
		if err != nil {
			continue
		}
		inst.DetectedLabel = c.label
		results = append(results, *inst)
	}
	return results
}

// looksLikeAntBrowserRoot 通过特征文件快速判定一个目录是否为 Ant Browser 运行根目录或用户状态目录。
func looksLikeAntBrowserRoot(dir string) bool {
	if fileExists(filepath.Join(dir, "ant-chrome.exe")) || fileExists(filepath.Join(dir, "ant-chrome")) {
		return true
	}
	if fileExists(filepath.Join(dir, "Contents", "MacOS", "ant-chrome")) {
		return true
	}
	if fileExists(filepath.Join(dir, "wails.json")) && fileExists(filepath.Join(dir, "bat", "dev.bat")) {
		return true
	}
	if fileExists(filepath.Join(dir, "data", "app.db")) {
		return true
	}
	if fileExists(filepath.Join(dir, "config.yaml")) && dirExists(filepath.Join(dir, "data")) {
		return true
	}
	return false
}

// loadProfilesFromDB 以只读快照方式读取 app.db 中的 browser_profiles，绝不触碰或锁定源库。
func loadProfilesFromDB(inst *AppInstallation, includeDeleted bool) ([]AppProfile, error) {
	if !fileExists(inst.DBPath) {
		return nil, fmt.Errorf("未找到数据库文件 %s（如果是全新安装的正式版，请先启动并正常退出一次 Ant Browser 完成初始化）", inst.DBPath)
	}

	snapshotPath, cleanup, err := snapshotSQLiteToTemp(inst.DBPath)
	if err != nil {
		return nil, fmt.Errorf("创建 app.db 只读快照失败: %w", err)
	}
	defer cleanup()

	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("打开 app.db 失败: %w", err)
	}
	defer db.Close()

	cols, err := tableColumns(db, "browser_profiles")
	if err != nil {
		return nil, fmt.Errorf("读取 browser_profiles 表结构失败: %w", err)
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("数据库缺少 browser_profiles 表: %s", inst.DBPath)
	}

	colText := func(name string, fallback string) string {
		if cols[name] {
			return fmt.Sprintf("COALESCE(%s, %s)", name, fallback)
		}
		return fallback
	}

	whereClause := ""
	if !includeDeleted && cols["deleted_at"] {
		whereClause = " WHERE COALESCE(deleted_at, '') = ''"
	}

	query := fmt.Sprintf(
		`SELECT profile_id, profile_name, %s, %s, %s, %s, %s, %s, %s, %s
		 FROM browser_profiles%s
		 ORDER BY created_at ASC, profile_name ASC`,
		colText("user_data_dir", "''"),
		colText("fingerprint_args", "'[]'"),
		colText("proxy_mode", "''"),
		colText("proxy_id", "''"),
		colText("proxy_config", "''"),
		colText("proxy_group_name", "''"),
		colText("proxy_bind_name", "''"),
		colText("deleted_at", "''"),
		whereClause,
	)
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("查询实例列表失败: %w", err)
	}
	defer rows.Close()

	var profiles []AppProfile
	for rows.Next() {
		var p AppProfile
		var fpRaw string
		if err := rows.Scan(
			&p.ProfileID,
			&p.ProfileName,
			&p.UserDataDir,
			&fpRaw,
			&p.ProxyMode,
			&p.ProxyID,
			&p.ProxyConfig,
			&p.ProxyGroupName,
			&p.ProxyBindName,
			&p.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("解析实例记录失败: %w", err)
		}
		p.ProfileID = strings.TrimSpace(p.ProfileID)
		p.ProfileName = strings.TrimSpace(p.ProfileName)
		p.UserDataDir = strings.TrimSpace(p.UserDataDir)
		p.ProxyMode = normalizeProxyMode(p.ProxyMode)
		p.ProxyID = strings.TrimSpace(p.ProxyID)
		p.ProxyConfig = strings.TrimSpace(p.ProxyConfig)
		p.ProxyGroupName = strings.TrimSpace(p.ProxyGroupName)
		p.ProxyBindName = strings.TrimSpace(p.ProxyBindName)
		p.DeletedAt = strings.TrimSpace(p.DeletedAt)
		if p.ProfileID == "" {
			continue
		}
		_ = json.Unmarshal([]byte(fpRaw), &p.FingerprintArgs)
		p.FingerprintHash = computeFingerprintHash(materializeEffectiveFingerprintArgs(p.ProfileID, p.FingerprintArgs))
		p.ResolvedDataDir = resolveProfileDataDir(inst, p.ProfileID, p.UserDataDir)
		profiles = append(profiles, p)
	}
	return profiles, rows.Err()
}

// countProfilesInDB 以只读快照方式统计 app.db 中的活跃实例与回收站实例数量（供交互菜单展示）。
func countProfilesInDB(dbPath string) (active int, deleted int, err error) {
	snapshotPath, cleanup, err := snapshotSQLiteToTemp(dbPath)
	if err != nil {
		return 0, 0, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return 0, 0, err
	}
	defer db.Close()

	cols, err := tableColumns(db, "browser_profiles")
	if err != nil || len(cols) == 0 {
		return 0, 0, err
	}
	if cols["deleted_at"] {
		_ = db.QueryRow(`SELECT COUNT(*) FROM browser_profiles WHERE COALESCE(deleted_at, '') = ''`).Scan(&active)
		_ = db.QueryRow(`SELECT COUNT(*) FROM browser_profiles WHERE COALESCE(deleted_at, '') != ''`).Scan(&deleted)
	} else {
		_ = db.QueryRow(`SELECT COUNT(*) FROM browser_profiles`).Scan(&active)
	}
	return active, deleted, nil
}

// createMinimalShellProfilesInDB 在目标 app.db 中创建最小空壳实例条目（不触碰代理/插件/书签/分组/config.yaml）。
// 代理与指纹默认留空，若用户显式开启 --sync-fingerprint 或 --sync-proxy，随后由 applyProfileExtrasInDB 统一写入。
func createMinimalShellProfilesInDB(inst *AppInstallation, toCreate []AppProfile) error {
	if len(toCreate) == 0 {
		return nil
	}
	if !fileExists(inst.DBPath) {
		return fmt.Errorf("目标数据库不存在: %s（请先启动并正常退出一次 Ant Browser 完成初始化）", inst.DBPath)
	}

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", filepath.ToSlash(inst.DBPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("打开目标数据库失败: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	colInfos, err := tableColumnDetails(db, "browser_profiles")
	if err != nil {
		return fmt.Errorf("读取目标 browser_profiles 表结构失败: %w", err)
	}
	if len(colInfos) == 0 {
		return fmt.Errorf("目标数据库缺少 browser_profiles 表")
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开启数据库事务失败: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().Format(time.RFC3339)
	for _, p := range toCreate {
		valuesByCol := map[string]any{
			"profile_id":       p.ProfileID,
			"profile_name":     p.ProfileName,
			"user_data_dir":    p.UserDataDir,
			"core_id":          "",
			"fingerprint_args": "[]",
			"proxy_id":         "",
			"proxy_config":     "",
			"launch_args":      "[]",
			"tags":             "[]",
			"keywords":         "[]",
			"created_at":       now,
			"updated_at":       now,
		}

		var cols []string
		var placeholders []string
		var args []any
		for _, ci := range colInfos {
			if val, ok := valuesByCol[ci.name]; ok {
				cols = append(cols, ci.name)
				placeholders = append(placeholders, "?")
				args = append(args, val)
				continue
			}
			// 兼容未来可能新增的 NOT NULL 且无默认值的列
			if ci.notNull && !ci.hasDefault {
				cols = append(cols, ci.name)
				placeholders = append(placeholders, "?")
				if strings.Contains(strings.ToUpper(ci.colType), "INT") {
					args = append(args, 0)
				} else {
					args = append(args, "")
				}
			}
		}

		stmt := fmt.Sprintf(
			"INSERT INTO browser_profiles (%s) VALUES (%s)",
			strings.Join(cols, ", "),
			strings.Join(placeholders, ", "),
		)
		if _, err := tx.Exec(stmt, args...); err != nil {
			return fmt.Errorf("创建目标空壳实例「%s」失败: %w", p.ProfileName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交目标数据库事务失败: %w", err)
	}
	return nil
}

// columnDetail 记录 SQLite 表单个列的元信息，用于跨版本动态拼装 INSERT 语句。
type columnDetail struct {
	name       string
	colType    string
	notNull    bool
	hasDefault bool
}

// tableColumnDetails 通过 PRAGMA table_info 读取表结构详情，兼容不同历史/未来版本的 app.db。
func tableColumnDetails(db *sql.DB, tableName string) ([]columnDetail, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []columnDetail
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		result = append(result, columnDetail{
			name:       strings.ToLower(strings.TrimSpace(name)),
			colType:    colType,
			notNull:    notNull != 0,
			hasDefault: dflt.Valid,
		})
	}
	return result, rows.Err()
}

// tableColumns 返回指定表所有小写列名集合，便于读取前动态检测可选列是否存在。
func tableColumns(db *sql.DB, tableName string) (map[string]bool, error) {
	details, err := tableColumnDetails(db, tableName)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(details))
	for _, d := range details {
		out[d.name] = true
	}
	return out, nil
}

// resolveProfileDataDir 解析实例对应的 Chromium --user-data-dir 绝对路径（默认以 profile_id 为子目录名）。
func resolveProfileDataDir(inst *AppInstallation, profileID, userDataDir string) string {
	dir := strings.TrimSpace(userDataDir)
	if dir == "" {
		dir = strings.TrimSpace(profileID)
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	return filepath.Join(inst.UserDataRoot, dir)
}

// resolveRelative 将相对路径基于 root 解析为绝对路径，若 p 已是绝对路径则直接清理返回。
func resolveRelative(root, p string) string {
	cleaned := strings.TrimSpace(p)
	if cleaned == "" {
		return filepath.Clean(root)
	}
	if filepath.IsAbs(cleaned) {
		return filepath.Clean(cleaned)
	}
	return filepath.Join(root, filepath.FromSlash(cleaned))
}

// computeFingerprintHash 对排序后的指纹参数计算 8 字节短 SHA-256 摘要，
// 仅用于导入预览阶段非敏感地提示源/目标指纹是否存在差异。
func computeFingerprintHash(args []string) string {
	if len(args) == 0 {
		return ""
	}
	norm := make([]string, 0, len(args))
	for _, a := range args {
		if t := strings.TrimSpace(a); t != "" {
			norm = append(norm, t)
		}
	}
	if len(norm) == 0 {
		return ""
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return hex.EncodeToString(sum[:8])
}

// newRandomUUIDv4 使用加密安全随机源生成标准 RFC 4122 UUID v4 字符串（零第三方 UUID 依赖）。
func newRandomUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// fileExists 判断指定路径是否存在且为常规文件。
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// dirExists 判断指定路径是否存在且为目录。
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
