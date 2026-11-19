package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	chromiumV10Prefix = "v10"
	chromiumV11Prefix = "v11"
	chromiumV20Prefix = "v20"
	gcmNonceSize      = 12
)

var googleRotatingCookieNames = map[string]bool{
	"__Secure-1PSIDTS": true,
	"__Secure-3PSIDTS": true,
	"SIDCC":            true,
	"__Secure-1PSIDCC": true,
	"__Secure-3PSIDCC": true,
}

type exportedCookiesResult struct {
	Dump                    ProfileCookieDump
	GoogleCookieCount       int
	HasRotatingGoogleTokens bool
	V20CookieCount          int
	DBSCSessionCount        int
	Warnings                []string
}

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

// exportProfileCookies 离线读取并解密单个实例的 Chromium Cookies 数据库，同时检测 v20 与 DBSC。
func exportProfileCookies(profile AppProfile) (*exportedCookiesResult, error) {
	result := &exportedCookiesResult{
		Dump: ProfileCookieDump{
			SchemaVersion: cookieDBVersionCurrent,
			ProfileID:     profile.ProfileID,
			ProfileName:   profile.ProfileName,
			Cookies:       []PortableCookieRecord{},
		},
	}

	// 检测是否存在硬件 TPM 绑定的 Device Bound Sessions (DBSC)
	dbscCount, dbscErr := countDBSCSessions(profile.ResolvedDataDir)
	if dbscErr != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("检查 Device Bound Sessions 失败: %v", dbscErr))
	} else if dbscCount > 0 {
		result.DBSCSessionCount = dbscCount
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("检测到 %d 条 Device Bound Sessions (DBSC) 硬件绑定会话，该类会话私钥锁定在本机 TPM，无法跨电脑迁移", dbscCount))
	}

	cookiesPath := locateCookiesDBPath(profile.ResolvedDataDir)
	if cookiesPath == "" {
		return result, nil
	}

	keyInfo, err := readLocalStateDPAPIKey(profile.ResolvedDataDir)
	if err != nil {
		return nil, fmt.Errorf("解包 Local State DPAPI 密钥失败: %w", err)
	}
	if keyInfo.AESKey != nil {
		defer zeroBytes(keyInfo.AESKey)
	}
	if keyInfo.HasAppBoundKey {
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

	var aead cipher.AEAD
	if len(keyInfo.AESKey) == 32 {
		block, cErr := aes.NewCipher(keyInfo.AESKey)
		if cErr != nil {
			return nil, fmt.Errorf("初始化 AES 解密器失败: %w", cErr)
		}
		aead, cErr = cipher.NewGCM(block)
		if cErr != nil {
			return nil, fmt.Errorf("初始化 AES-GCM 解密器失败: %w", cErr)
		}
	}

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
			if len(encVal) < 3 {
				unknownPrefixCount++
				continue
			}
			prefix := string(encVal[:3])
			switch prefix {
			case chromiumV10Prefix, chromiumV11Prefix:
				if aead == nil {
					return nil, fmt.Errorf("存在加密 Cookie，但缺少可用的 Local State DPAPI 密钥")
				}
				plain, hashMatched, decErr := decryptChromiumV10Cookie(aead, encVal, rec.HostKey, schemaVer)
				if decErr != nil {
					return nil, fmt.Errorf("解密 Cookie (%s / %s) 失败: %w", rec.HostKey, rec.Name, decErr)
				}
				if schemaVer >= 24 && !hashMatched {
					hashMismatchCount++
				}
				rec.Value = plain
				rec.WasPlaintext = false
			case chromiumV20Prefix:
				result.V20CookieCount++
				continue
			default:
				// 极老版本 Windows DPAPI 直接加密的 Cookie（无 v10 前缀）
				if plainBytes, dErr := dpapiUnprotect(encVal); dErr == nil {
					rec.Value = string(plainBytes)
					rec.WasPlaintext = false
				} else {
					unknownPrefixCount++
					continue
				}
			}
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

func decryptChromiumV10Cookie(aead cipher.AEAD, encVal []byte, hostKey string, schemaVer int) (value string, hashMatched bool, err error) {
	if len(encVal) < 3+gcmNonceSize+aead.Overhead() {
		return "", false, errors.New("v10 密文长度不足")
	}
	nonce := encVal[3 : 3+gcmNonceSize]
	ciphertext := encVal[3+gcmNonceSize:]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", false, err
	}
	defer zeroBytes(plain)

	if schemaVer >= 24 {
		expectedHash := sha256.Sum256([]byte(hostKey))
		if len(plain) >= sha256.Size && bytes.Equal(plain[:sha256.Size], expectedHash[:]) {
			return string(plain[sha256.Size:]), true, nil
		}
		return string(plain), false, nil
	}
	return string(plain), true, nil
}

func encryptChromiumV10Cookie(aead cipher.AEAD, hostKey string, value string) ([]byte, error) {
	hostHash := sha256.Sum256([]byte(hostKey))
	plain := make([]byte, sha256.Size+len(value))
	copy(plain[:sha256.Size], hostHash[:])
	copy(plain[sha256.Size:], value)
	defer zeroBytes(plain)

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 Cookie 随机数失败: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, len(chromiumV10Prefix)+len(nonce)+len(sealed))
	out = append(out, []byte(chromiumV10Prefix)...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

func cookieUniqueKey(c PortableCookieRecord) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s\x00%d\x00%d",
		c.HostKey, c.TopFrameSiteKey, c.HasCrossSiteAncestor, c.Name, c.Path, c.SourceScheme, c.SourcePort)
}

// importProfileCookies 使用目标机 DPAPI 主密钥重新加密并原子写入 Default/Network/Cookies（Chromium v24 规范）。
func importProfileCookies(targetUserDataDir string, dump ProfileCookieDump, cookieMode string, backupDir string) (written int, reusedKey bool, err error) {
	aesKey, reused, err := ensureTargetLocalStateDPAPIKey(targetUserDataDir)
	if err != nil {
		return 0, false, err
	}
	defer zeroBytes(aesKey)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return 0, reused, fmt.Errorf("创建目标 AES 加密器失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return 0, reused, fmt.Errorf("创建目标 AES-GCM 加密器失败: %w", err)
	}

	finalCookies := dump.Cookies
	if strings.EqualFold(cookieMode, "merge") {
		existingRes, readErr := exportProfileCookies(AppProfile{
			ProfileID:       dump.ProfileID,
			ProfileName:     dump.ProfileName,
			ResolvedDataDir: targetUserDataDir,
		})
		if readErr == nil && existingRes != nil && len(existingRes.Dump.Cookies) > 0 {
			merged := make([]PortableCookieRecord, 0, len(existingRes.Dump.Cookies)+len(dump.Cookies))
			indexByKey := make(map[string]int, len(existingRes.Dump.Cookies)+len(dump.Cookies))
			for _, c := range existingRes.Dump.Cookies {
				k := cookieUniqueKey(c)
				indexByKey[k] = len(merged)
				merged = append(merged, c)
			}
			for _, c := range dump.Cookies {
				k := cookieUniqueKey(c)
				if idx, ok := indexByKey[k]; ok {
					merged[idx] = c
				} else {
					indexByKey[k] = len(merged)
					merged = append(merged, c)
				}
			}
			finalCookies = merged
		}
	}

	networkDir := filepath.Join(targetUserDataDir, "Default", "Network")
	if err := os.MkdirAll(networkDir, 0o755); err != nil {
		return 0, reused, fmt.Errorf("创建目标 Default/Network 目录失败: %w", err)
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
		return 0, reused, fmt.Errorf("创建临时 Cookies 数据库失败: %w", err)
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

		for _, c := range finalCookies {
			plainVal := ""
			var encVal []byte
			if c.WasPlaintext && c.Value != "" {
				plainVal = c.Value
				encVal = []byte{}
			} else {
				var encErr error
				encVal, encErr = encryptChromiumV10Cookie(aead, c.HostKey, c.Value)
				if encErr != nil {
					return encErr
				}
			}

			if _, err := insertStmt.Exec(
				c.CreationUTC,
				c.HostKey,
				c.TopFrameSiteKey,
				c.Name,
				plainVal,
				encVal,
				c.Path,
				c.ExpiresUTC,
				c.IsSecure,
				c.IsHTTPOnly,
				c.LastAccessUTC,
				c.HasExpires,
				c.IsPersistent,
				c.Priority,
				c.SameSite,
				c.SourceScheme,
				c.SourcePort,
				c.LastUpdateUTC,
				c.SourceType,
				c.HasCrossSiteAncestor,
			); err != nil {
				return fmt.Errorf("写入 Cookie (%s / %s) 失败: %w", c.HostKey, c.Name, err)
			}
		}

		return tx.Commit()
	}()
	if buildErr != nil {
		return 0, reused, buildErr
	}

	targetCookiesPath := filepath.Join(networkDir, "Cookies")
	if backupDir != "" {
		for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
			src := targetCookiesPath + suffix
			if fileExists(src) {
				dst := filepath.Join(backupDir, "Default", "Network", "Cookies"+suffix)
				if err := copyFile(src, dst); err != nil {
					return 0, reused, fmt.Errorf("备份原 Cookies 文件失败: %w", err)
				}
			}
		}
	}

	// 清理旧的 journal/wal/shm 避免和新的 Cookies 数据库不一致
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		_ = os.Remove(targetCookiesPath + suffix)
	}

	if err := atomicReplaceFile(tmpDBPath, targetCookiesPath); err != nil {
		return 0, reused, fmt.Errorf("替换目标 Cookies 数据库失败: %w", err)
	}

	// 写入 Chromium Network Service 迁移检查点标记，确保新实例启动时直接读取 Default/Network/Cookies
	migratedMarker := filepath.Join(networkDir, "NetworkDataMigrated")
	if !fileExists(migratedMarker) {
		_ = os.WriteFile(migratedMarker, []byte{}, 0o644)
	}

	return len(finalCookies), reused, nil
}

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
