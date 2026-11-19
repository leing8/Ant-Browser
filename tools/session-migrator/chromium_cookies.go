// chromium_cookies.go 负责离线读写 Chromium Cookies SQLite 数据库（严格兼容 schema v24）、
// 检测硬件绑定会话（Device Bound Sessions / DBSC）与 v20 加密，以及按平台加解密器完成 Cookie 重加密与原子落盘。
package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	// chromiumV10Prefix / chromiumV11Prefix 为常规 OS 加密前缀（Windows AES-GCM / macOS AES-CBC）。
	chromiumV10Prefix = "v10"
	chromiumV11Prefix = "v11"
	// chromiumV20Prefix 为 Chrome 127+ Windows App-Bound Encryption 前缀，需要系统级 Elevation Service。
	chromiumV20Prefix = "v20"
	// gcmNonceSize 为 Windows AES-256-GCM 密文头部随机数长度（96 bit）。
	gcmNonceSize = 12
)

// googleRotatingCookieNames 列出 Google 实时动态轮转的会话安全 Cookie 名称，
// 用于在导出/导入摘要中提醒用户切勿双机并发使用同一 Google 会话。
var googleRotatingCookieNames = map[string]bool{
	"__Secure-1PSIDTS": true,
	"__Secure-3PSIDTS": true,
	"SIDCC":            true,
	"__Secure-1PSIDCC": true,
	"__Secure-3PSIDCC": true,
}

// sampleEncryptedCookie 保存少量真实密文样本，供 macOS 端在多个钥匙串候选中做 SHA256(host_key) 验签。
type sampleEncryptedCookie struct {
	HostKey   string
	EncVal    []byte
	SchemaVer int
}

// exportedCookiesResult 汇总单个实例离线解密后的 Cookie 集合、Google 风控特征计数与告警信息。
type exportedCookiesResult struct {
	Dump                    ProfileCookieDump
	GoogleCookieCount       int
	HasRotatingGoogleTokens bool
	V20CookieCount          int
	DBSCSessionCount        int
	Warnings                []string
}

// locateCookiesDBPath 优先定位 Chromium 96+ 沙箱路径 Default/Network/Cookies，兼容更早期版本的 Default/Cookies。
func locateCookiesDBPath(userDataDir string) string {
	modern := filepath.Join(userDataDir, "Default", "Network", "Cookies")
	if fileExists(modern) {
		return modern
	}
	legacy := filepath.Join(userDataDir, "Default", "Cookies")
	if fileExists(legacy) {
		return legacy
	}
	return ""
}

// exportProfileCookies 离线读取并解密单个实例的 Chromium Cookies 数据库（自动适配 Windows DPAPI 与 macOS Keychain）。
func exportProfileCookies(profile AppProfile) (*exportedCookiesResult, error) {
	return exportProfileCookiesWithOptions(profile, nil, cookieCryptoOptions{})
}

// exportProfileCookiesWithOptions 按给定安装信息与平台加密选项离线读取并解密实例 Cookie。
func exportProfileCookiesWithOptions(profile AppProfile, inst *AppInstallation, cryptoOpts cookieCryptoOptions) (*exportedCookiesResult, error) {
	cookiesPath := locateCookiesDBPath(profile.ResolvedDataDir)
	if cookiesPath == "" {
		return exportProfileCookiesWithCipher(profile, nil)
	}

	// 预取最多 3 条 v10/v11 样本供 macOS 多钥匙串候选精确验签
	samples := readSampleEncryptedCookies(cookiesPath, 3)
	c, err := openExportCookieCipher(profile.ResolvedDataDir, inst, cryptoOpts, samples)
	if err != nil {
		return nil, fmt.Errorf("初始化 Cookie 解密密钥失败（%s）: %w", platformCryptoLabel(), err)
	}
	defer c.Close()

	return exportProfileCookiesWithCipher(profile, c)
}

// exportProfileCookiesWithCipher 使用指定 cookieCipher 解密实例 Cookies SQLite（与平台密钥源解耦，便于跨系统测试）。
func exportProfileCookiesWithCipher(profile AppProfile, c cookieCipher) (*exportedCookiesResult, error) {
	result := &exportedCookiesResult{
		Dump: ProfileCookieDump{
			SchemaVersion: cookieDBVersionCurrent,
			ProfileID:     profile.ProfileID,
			ProfileName:   profile.ProfileName,
			Cookies:       []PortableCookieRecord{},
		},
	}

	// 检测是否存在硬件 TPM / Secure Enclave 绑定的 Device Bound Sessions (DBSC)
	dbscCount, dbscErr := countDBSCSessions(profile.ResolvedDataDir)
	if dbscErr != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("检查 Device Bound Sessions 失败: %v", dbscErr))
	} else if dbscCount > 0 {
		result.DBSCSessionCount = dbscCount
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("检测到 %d 条 Device Bound Sessions (DBSC) 硬件绑定会话，该类会话私钥锁定在本机硬件安全模块，无法跨电脑迁移", dbscCount))
	}

	cookiesPath := locateCookiesDBPath(profile.ResolvedDataDir)
	if cookiesPath == "" {
		return result, nil
	}

	if c != nil && c.HasAppBoundKey() {
		result.Warnings = append(result.Warnings, "Local State 包含 app_bound_encrypted_key（若存在 v20 Cookie 将无法离线迁移）")
	}

	snapshotPath, cleanup, err := snapshotSQLiteToTemp(cookiesPath)
	if err != nil {
		return nil, fmt.Errorf("复制 Cookies 快照失败: %w", err)
	}
	defer cleanup()

	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("打开 Cookies 数据库失败: %w", err)
	}
	defer db.Close()

	schemaVer := readCookiesSchemaVersion(db)
	result.Dump.SchemaVersion = schemaVer

	cols, err := tableColumns(db, "cookies")
	if err != nil {
		return nil, fmt.Errorf("读取 cookies 表结构失败: %w", err)
	}
	if len(cols) == 0 {
		return result, nil
	}

	colOrZero := func(name string) string {
		if cols[name] {
			return name
		}
		return "0"
	}
	colOrEmpty := func(name string) string {
		if cols[name] {
			return name
		}
		return "''"
	}

	query := fmt.Sprintf(`
		SELECT
			%s, %s, %s, %s, %s, encrypted_value, %s, %s,
			%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
		FROM cookies
		ORDER BY creation_utc ASC, host_key ASC, name ASC`,
		colOrZero("creation_utc"),
		colOrEmpty("host_key"),
		colOrEmpty("top_frame_site_key"),
		colOrEmpty("name"),
		colOrEmpty("value"),
		colOrEmpty("path"),
		colOrZero("expires_utc"),
		colOrZero("is_secure"),
		colOrZero("is_httponly"),
		colOrZero("last_access_utc"),
		colOrZero("has_expires"),
		colOrZero("is_persistent"),
		colOrZero("priority"),
		colOrZero("samesite"),
		colOrZero("source_scheme"),
		colOrZero("source_port"),
		colOrZero("last_update_utc"),
		colOrZero("source_type"),
		colOrZero("has_cross_site_ancestor"),
	)

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("查询 Cookies 行失败: %w", err)
	}
	defer rows.Close()

	hashMismatchCount := 0
	unknownPrefixCount := 0

	for rows.Next() {
		var rec PortableCookieRecord
		var encVal []byte
		if err := rows.Scan(
			&rec.CreationUTC,
			&rec.HostKey,
			&rec.TopFrameSiteKey,
			&rec.Name,
			&rec.Value,
			&encVal,
			&rec.Path,
			&rec.ExpiresUTC,
			&rec.IsSecure,
			&rec.IsHTTPOnly,
			&rec.LastAccessUTC,
			&rec.HasExpires,
			&rec.IsPersistent,
			&rec.Priority,
			&rec.SameSite,
			&rec.SourceScheme,
			&rec.SourcePort,
			&rec.LastUpdateUTC,
			&rec.SourceType,
			&rec.HasCrossSiteAncestor,
		); err != nil {
			return nil, fmt.Errorf("读取 Cookie 记录失败: %w", err)
		}

		if len(encVal) > 0 {
			if c == nil {
				return nil, fmt.Errorf("存在加密 Cookie，但缺少可用的平台解密密钥")
			}
			plain, hashMatched, skippedV20, unknownPrefix, decErr := c.DecryptCookie(encVal, rec.HostKey, schemaVer)
			if decErr != nil {
				return nil, fmt.Errorf("解密 Cookie (%s / %s) 失败: %w", rec.HostKey, rec.Name, decErr)
			}
			if skippedV20 {
				result.V20CookieCount++
				continue
			}
			if unknownPrefix {
				unknownPrefixCount++
				continue
			}
			if schemaVer >= 24 && !hashMatched {
				hashMismatchCount++
			}
			rec.Value = plain
			rec.WasPlaintext = false
		} else {
			rec.WasPlaintext = true
		}

		if isGoogleDomain(rec.HostKey) {
			result.GoogleCookieCount++
			if googleRotatingCookieNames[rec.Name] {
				result.HasRotatingGoogleTokens = true
			}
		}
		result.Dump.Cookies = append(result.Dump.Cookies, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if result.V20CookieCount > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("发现 %d 条 v20 App-Bound 加密 Cookie（需要官方 Chrome Elevation Service，离线工具无法解密，已跳过）", result.V20CookieCount))
	}
	if hashMismatchCount > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("有 %d 条 Cookie 未携带标准 v24 域名 SHA256 前缀，已按兼容模式保留明文", hashMismatchCount))
	}
	if unknownPrefixCount > 0 {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("跳过 %d 条无法识别加密格式的 Cookie", unknownPrefixCount))
	}

	return result, nil
}

// readSampleEncryptedCookies 从 Cookies 只读快照中抽取最多 limit 条 v10/v11 密文样本用于密钥校验。
func readSampleEncryptedCookies(cookiesPath string, limit int) []sampleEncryptedCookie {
	snapshotPath, cleanup, err := snapshotSQLiteToTemp(cookiesPath)
	if err != nil {
		return nil
	}
	defer cleanup()

	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return nil
	}
	defer db.Close()

	schemaVer := readCookiesSchemaVersion(db)
	rows, err := db.Query(`SELECT host_key, encrypted_value FROM cookies WHERE length(encrypted_value) > 3 LIMIT ?`, limit*3)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var samples []sampleEncryptedCookie
	for rows.Next() && len(samples) < limit {
		var host string
		var enc []byte
		if rows.Scan(&host, &enc) == nil && len(enc) > 3 {
			pref := string(enc[:3])
			if pref == chromiumV10Prefix || pref == chromiumV11Prefix {
				samples = append(samples, sampleEncryptedCookie{
					HostKey:   host,
					EncVal:    append([]byte(nil), enc...),
					SchemaVer: schemaVer,
				})
			}
		}
	}
	return samples
}

// cookieUniqueKey 构造与 Chromium cookies_unique_index 完全一致的 7 元组复合键，供 merge 模式去重覆盖。
func cookieUniqueKey(c PortableCookieRecord) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s\x00%d\x00%d",
		c.HostKey, c.TopFrameSiteKey, c.HasCrossSiteAncestor, c.Name, c.Path, c.SourceScheme, c.SourcePort)
}

// importProfileCookies 使用目标机原生加密机制重新加密并原子写入 Default/Network/Cookies（Chromium v24 规范）。
func importProfileCookies(targetUserDataDir string, dump ProfileCookieDump, cookieMode string, backupDir string) (written int, reusedKey bool, err error) {
	w, reused, _, err := importProfileCookiesWithOptions(targetUserDataDir, nil, cookieCryptoOptions{}, dump, cookieMode, backupDir)
	return w, reused, err
}

// importProfileCookiesWithOptions 获取/初始化目标机密钥并完成 Cookie 重加密原子写入，同时返回平台提示信息。
func importProfileCookiesWithOptions(targetUserDataDir string, inst *AppInstallation, cryptoOpts cookieCryptoOptions, dump ProfileCookieDump, cookieMode string, backupDir string) (written int, reusedKey bool, notice string, err error) {
	c, reused, err := ensureImportCookieCipher(targetUserDataDir, inst, cryptoOpts)
	if err != nil {
		return 0, false, "", err
	}
	defer c.Close()

	written, err = importProfileCookiesWithCipher(targetUserDataDir, c, dump, cookieMode, backupDir)
	return written, reused, c.Notice(), err
}

// importProfileCookiesWithCipher 使用指定 cookieCipher 重建符合 Chromium 144 (v24) 规范的 Cookies 数据库并原子替换。
func importProfileCookiesWithCipher(targetUserDataDir string, c cookieCipher, dump ProfileCookieDump, cookieMode string, backupDir string) (written int, err error) {
	finalCookies := dump.Cookies
	if strings.EqualFold(cookieMode, "merge") {
		existingRes, readErr := exportProfileCookiesWithCipher(AppProfile{
			ProfileID:       dump.ProfileID,
			ProfileName:     dump.ProfileName,
			ResolvedDataDir: targetUserDataDir,
		}, c)
		if readErr == nil && existingRes != nil && len(existingRes.Dump.Cookies) > 0 {
			merged := make([]PortableCookieRecord, 0, len(existingRes.Dump.Cookies)+len(dump.Cookies))
			indexByKey := make(map[string]int, len(existingRes.Dump.Cookies)+len(dump.Cookies))
			for _, item := range existingRes.Dump.Cookies {
				k := cookieUniqueKey(item)
				indexByKey[k] = len(merged)
				merged = append(merged, item)
			}
			for _, item := range dump.Cookies {
				k := cookieUniqueKey(item)
				if idx, ok := indexByKey[k]; ok {
					merged[idx] = item
				} else {
					indexByKey[k] = len(merged)
					merged = append(merged, item)
				}
			}
			finalCookies = merged
		}
	}

	networkDir := filepath.Join(targetUserDataDir, "Default", "Network")
	if err := os.MkdirAll(networkDir, 0o755); err != nil {
		return 0, fmt.Errorf("创建目标 Default/Network 目录失败: %w", err)
	}

	tmpDBPath := filepath.Join(networkDir, fmt.Sprintf("Cookies.migrator.%d.tmp", os.Getpid()))
	_ = os.Remove(tmpDBPath)
	defer func() {
		_ = os.Remove(tmpDBPath)
		_ = os.Remove(tmpDBPath + "-journal")
		_ = os.Remove(tmpDBPath + "-wal")
		_ = os.Remove(tmpDBPath + "-shm")
	}()

	db, err := sql.Open("sqlite", tmpDBPath)
	if err != nil {
		return 0, fmt.Errorf("创建临时 Cookies 数据库失败: %w", err)
	}
	db.SetMaxOpenConns(1)

	buildErr := func() error {
		defer db.Close()

		initStmts := []string{
			`PRAGMA page_size = 4096`,
			`PRAGMA journal_mode = DELETE`,
			`PRAGMA auto_vacuum = 0`,
			`CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)`,
			fmt.Sprintf(`INSERT INTO meta(key, value) VALUES ('version', '%d')`, cookieDBVersionCurrent),
			fmt.Sprintf(`INSERT INTO meta(key, value) VALUES ('last_compatible_version', '%d')`, cookieDBVersionCurrent),
			`INSERT INTO meta(key, value) VALUES ('mmap_status', '-1')`,
			`CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,has_cross_site_ancestor INTEGER NOT NULL)`,
			`CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port)`,
		}
		for _, stmt := range initStmts {
			if _, err := db.Exec(stmt); err != nil {
				return fmt.Errorf("初始化 Cookies 表结构失败: %w", err)
			}
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		insertStmt, err := tx.Prepare(`
			INSERT OR REPLACE INTO cookies(
				creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path,
				expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent,
				priority, samesite, source_scheme, source_port, last_update_utc, source_type,
				has_cross_site_ancestor
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer insertStmt.Close()

		for _, rec := range finalCookies {
			plainVal := ""
			var encVal []byte
			if rec.WasPlaintext && rec.Value != "" {
				plainVal = rec.Value
				encVal = []byte{}
			} else {
				var encErr error
				encVal, encErr = c.EncryptCookie(rec.HostKey, rec.Value)
				if encErr != nil {
					return encErr
				}
			}

			if _, err := insertStmt.Exec(
				rec.CreationUTC,
				rec.HostKey,
				rec.TopFrameSiteKey,
				rec.Name,
				plainVal,
				encVal,
				rec.Path,
				rec.ExpiresUTC,
				rec.IsSecure,
				rec.IsHTTPOnly,
				rec.LastAccessUTC,
				rec.HasExpires,
				rec.IsPersistent,
				rec.Priority,
				rec.SameSite,
				rec.SourceScheme,
				rec.SourcePort,
				rec.LastUpdateUTC,
				rec.SourceType,
				rec.HasCrossSiteAncestor,
			); err != nil {
				return fmt.Errorf("写入 Cookie (%s / %s) 失败: %w", rec.HostKey, rec.Name, err)
			}
		}

		return tx.Commit()
	}()
	if buildErr != nil {
		return 0, buildErr
	}

	targetCookiesPath := filepath.Join(networkDir, "Cookies")
	if backupDir != "" {
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			src := targetCookiesPath + suffix
			if fileExists(src) {
				dst := filepath.Join(backupDir, "Default", "Network", "Cookies"+suffix)
				if err := copyFile(src, dst); err != nil {
					return 0, fmt.Errorf("备份原 Cookies 文件失败: %w", err)
				}
			}
		}
	}

	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		_ = os.Remove(targetCookiesPath + suffix)
	}

	if err := atomicReplaceFile(tmpDBPath, targetCookiesPath); err != nil {
		return 0, fmt.Errorf("替换目标 Cookies 数据库失败: %w", err)
	}

	migratedMarker := filepath.Join(networkDir, "NetworkDataMigrated")
	if !fileExists(migratedMarker) {
		_ = os.WriteFile(migratedMarker, []byte{}, 0o644)
	}

	return len(finalCookies), nil
}

// readCookiesSchemaVersion 读取 Cookies 库 meta.version 字段，读取失败时按当前版本 24 处理。
func readCookiesSchemaVersion(db *sql.DB) int {
	var raw string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'version'`).Scan(&raw); err != nil {
		return cookieDBVersionCurrent
	}
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && v > 0 {
		return v
	}
	return cookieDBVersionCurrent
}

// countDBSCSessions 统计 Default/Network/Device Bound Sessions 中的硬件绑定会话行数，用于提前预警不可跨机迁移的 DBSC 会话。
func countDBSCSessions(userDataDir string) (int, error) {
	dbscPath := filepath.Join(userDataDir, "Default", "Network", "Device Bound Sessions")
	if !fileExists(dbscPath) {
		return 0, nil
	}
	snapshotPath, cleanup, err := snapshotSQLiteToTemp(dbscPath)
	if err != nil {
		return 0, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", snapshotPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name != 'meta'`)
	if err != nil {
		return 0, err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			tables = append(tables, name)
		}
	}
	rows.Close()

	total := 0
	for _, tbl := range tables {
		var cnt int
		escaped := strings.ReplaceAll(tbl, `"`, `""`)
		if err := db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM "%s"`, escaped)).Scan(&cnt); err == nil {
			total += cnt
		}
	}
	return total, nil
}

// isGoogleDomain 判断 host_key 是否属于 Google / YouTube 生态域名，仅用于统计摘要。
func isGoogleDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	h = strings.TrimPrefix(h, ".")
	for _, suffix := range []string{
		"google.com",
		"youtube.com",
		"gstatic.com",
		"googleapis.com",
		"googleusercontent.com",
		"googlevideo.com",
		"gmail.com",
		"google.co.jp",
		"google.co.uk",
		"google.com.hk",
		"google.com.tw",
	} {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	return strings.Contains(h, ".google.")
}

// snapshotSQLiteToTemp 将 SQLite 主库及配套 -wal/-shm/-journal 复制到临时目录供安全只读查询。
func snapshotSQLiteToTemp(dbPath string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "ant-sess-sqlite-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	baseName := filepath.Base(dbPath)
	dstMain := filepath.Join(tmpDir, baseName)
	if err := copyFile(dbPath, dstMain); err != nil {
		cleanup()
		return "", func() {}, err
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		src := dbPath + suffix
		if fileExists(src) {
			if err := copyFile(src, dstMain+suffix); err != nil {
				cleanup()
				return "", func() {}, err
			}
		}
	}
	return dstMain, cleanup, nil
}
