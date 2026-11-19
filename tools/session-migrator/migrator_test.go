//go:build windows

// migrator_test.go 覆盖 DPAPI 往返、加密/明文迁移包、已有/空目标导入、DBSC 与 v20 检测、
// 可选代理与指纹迁移（含去重与冲突保护）、真实 Chromium 144 内核离线解密与进程占锁集成验证，
// 以及 macOS AES-128-CBC/PBKDF2 与 Windows ↔ macOS 跨系统往返测试。
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// createTestAppRoot 在临时目录构建包含 config.yaml 与空表结构 data/app.db 的模拟 Ant Browser 实例根目录。
func createTestAppRoot(t *testing.T, profiles []AppProfile) string {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	cfg := "database:\n  sqlite:\n    path: data/app.db\nbrowser:\n  user_data_root: data\n"
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	dbPath := filepath.Join(dataDir, "app.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open test app.db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE browser_profiles (
			profile_id            TEXT PRIMARY KEY,
			profile_name          TEXT NOT NULL,
			user_data_dir         TEXT NOT NULL DEFAULT '',
			core_id               TEXT NOT NULL DEFAULT '',
			fingerprint_args      TEXT NOT NULL DEFAULT '[]',
			proxy_id              TEXT NOT NULL DEFAULT '',
			proxy_config          TEXT NOT NULL DEFAULT '',
			proxy_mode            TEXT NOT NULL DEFAULT '',
			proxy_group_name      TEXT NOT NULL DEFAULT '',
			proxy_bind_source_id  TEXT NOT NULL DEFAULT '',
			proxy_bind_source_url TEXT NOT NULL DEFAULT '',
			proxy_bind_name       TEXT NOT NULL DEFAULT '',
			proxy_bind_updated_at TEXT NOT NULL DEFAULT '',
			launch_args           TEXT NOT NULL DEFAULT '[]',
			tags                  TEXT NOT NULL DEFAULT '[]',
			keywords              TEXT NOT NULL DEFAULT '[]',
			group_id              TEXT NOT NULL DEFAULT '',
			created_at            DATETIME NOT NULL,
			updated_at            DATETIME NOT NULL,
			deleted_at            TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE browser_proxies (
			proxy_id          TEXT PRIMARY KEY,
			proxy_name        TEXT NOT NULL,
			proxy_config      TEXT NOT NULL,
			preferred_kernel  TEXT NOT NULL DEFAULT '',
			dns_servers       TEXT NOT NULL DEFAULT '',
			group_name        TEXT NOT NULL DEFAULT '',
			source_url        TEXT NOT NULL DEFAULT '',
			last_latency_ms   INTEGER NOT NULL DEFAULT -1,
			sort_order        INTEGER NOT NULL DEFAULT 0,
			created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE browser_proxy_virtual_groups (
			group_id           TEXT PRIMARY KEY,
			group_name         TEXT NOT NULL COLLATE NOCASE UNIQUE,
			strategy           TEXT NOT NULL DEFAULT 'round_robin',
			selected_proxy_id  TEXT NOT NULL DEFAULT '',
			member_proxy_ids   TEXT NOT NULL DEFAULT '[]',
			member_group_names TEXT NOT NULL DEFAULT '[]',
			sort_order         INTEGER NOT NULL DEFAULT 0,
			created_at         TEXT NOT NULL DEFAULT '',
			updated_at         TEXT NOT NULL DEFAULT ''
		);`)
	if err != nil {
		t.Fatalf("create test tables: %v", err)
	}

	now := time.Now().Format(time.RFC3339)
	for _, p := range profiles {
		fpBytes, _ := json.Marshal(p.FingerprintArgs)
		udd := p.UserDataDir
		if udd == "" {
			udd = p.ProfileID
		}
		_, err = db.Exec(`
			INSERT INTO browser_profiles
				(profile_id, profile_name, user_data_dir, fingerprint_args, proxy_mode, proxy_id, proxy_config, proxy_group_name, proxy_bind_name, created_at, updated_at, deleted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ProfileID, p.ProfileName, udd, string(fpBytes), p.ProxyMode, p.ProxyID, p.ProxyConfig, p.ProxyGroupName, p.ProxyBindName, now, now, p.DeletedAt,
		)
		if err != nil {
			t.Fatalf("insert profile %s: %v", p.ProfileID, err)
		}
	}
	return root
}

// TestDPAPIRoundTrip 验证本机 Windows DPAPI 加解密往返一致且密文不等于明文。
func TestDPAPIRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	enc, err := dpapiProtect(secret)
	if err != nil {
		t.Fatalf("dpapiProtect failed: %v", err)
	}
	if bytes.Equal(enc, secret) {
		t.Fatal("DPAPI output matches plaintext")
	}
	dec, err := dpapiUnprotect(enc)
	if err != nil {
		t.Fatalf("dpapiUnprotect failed: %v", err)
	}
	if !bytes.Equal(dec, secret) {
		t.Fatalf("dpapiUnprotect mismatch: got %x want %x", dec, secret)
	}
}

// TestFullExportImportToExistingAndMissingTargets 验证加密/明文导出导入至已有实例与自动建空壳实例的完整闭环，
// 确保默认纯登录态模式绝不篡改目标指纹、代理或无关配置。
func TestFullExportImportToExistingAndMissingTargets(t *testing.T) {
	srcProfile := AppProfile{
		ProfileID:       "11111111-1111-4111-8111-111111111111",
		ProfileName:     "Google 主号",
		UserDataDir:     "11111111-1111-4111-8111-111111111111",
		FingerprintArgs: []string{"--fingerprint=99887766", "--lang=en-US"},
	}
	srcRoot := createTestAppRoot(t, []AppProfile{srcProfile})
	srcDataDir := filepath.Join(srcRoot, "data", srcProfile.ProfileID)

	// 使用工具写入标准 Chromium v24 Cookies + Local State
	sampleCookies := []PortableCookieRecord{
		{
			CreationUTC:          13370000000000000,
			HostKey:              ".google.com",
			TopFrameSiteKey:      "",
			Name:                 "SID",
			Value:                "dummy-sid-token-123",
			Path:                 "/",
			ExpiresUTC:           13450000000000000,
			IsSecure:             1,
			IsHTTPOnly:           1,
			LastAccessUTC:        13370000010000000,
			HasExpires:           1,
			IsPersistent:         1,
			Priority:             2,
			SameSite:             -1,
			SourceScheme:         2,
			SourcePort:           443,
			LastUpdateUTC:        13370000010000000,
			SourceType:           1,
			HasCrossSiteAncestor: 0,
		},
		{
			CreationUTC:          13370000000000001,
			HostKey:              ".google.com",
			TopFrameSiteKey:      "",
			Name:                 "__Secure-1PSIDTS",
			Value:                "dummy-rotating-token-xyz",
			Path:                 "/",
			ExpiresUTC:           13450000000000000,
			IsSecure:             1,
			IsHTTPOnly:           1,
			LastAccessUTC:        13370000020000000,
			HasExpires:           1,
			IsPersistent:         1,
			Priority:             2,
			SameSite:             0,
			SourceScheme:         2,
			SourcePort:           443,
			LastUpdateUTC:        13370000020000000,
			SourceType:           1,
			HasCrossSiteAncestor: 0,
		},
	}

	if _, _, err := importProfileCookies(srcDataDir, ProfileCookieDump{
		SchemaVersion: cookieDBVersionCurrent,
		ProfileID:     srcProfile.ProfileID,
		ProfileName:   srcProfile.ProfileName,
		Cookies:       sampleCookies,
	}, "replace", ""); err != nil {
		t.Fatalf("seed source cookies failed: %v", err)
	}

	// 写入 Local Storage、Session Storage 以及应跳过的 LOCK 文件
	lsDir := filepath.Join(srcDataDir, "Default", "Local Storage", "leveldb")
	ssDir := filepath.Join(srcDataDir, "Default", "Session Storage")
	_ = os.MkdirAll(lsDir, 0o755)
	_ = os.MkdirAll(ssDir, 0o755)
	_ = os.WriteFile(filepath.Join(lsDir, "CURRENT"), []byte("MANIFEST-000001\n"), 0o644)
	_ = os.WriteFile(filepath.Join(lsDir, "000003.log"), []byte("ls-token-payload"), 0o644)
	_ = os.WriteFile(filepath.Join(lsDir, "LOCK"), []byte("lock"), 0o644)
	_ = os.WriteFile(filepath.Join(ssDir, "000001.ldb"), []byte("ss-token-payload"), 0o644)

	// 写入不应被迁移的非登录态文件（Preferences）
	_ = os.WriteFile(filepath.Join(srcDataDir, "Default", "Preferences"), []byte(`{"marker":"source-only"}`), 0o644)

	// 1. 测试密码加密导出
	encArchive := filepath.Join(t.TempDir(), "sessions-enc.antsess")
	expSummary, err := runExport(ExportOptions{
		AppRoot:               srcRoot,
		OutputPath:            encArchive,
		Password:              "TestPass123!",
		IncludeLocalStorage:   true,
		IncludeSessionStorage: true,
	})
	if err != nil {
		t.Fatalf("runExport (encrypted) failed: %v", err)
	}
	if expSummary.ExportedProfiles != 1 || expSummary.TotalCookies != 2 || expSummary.TotalGoogleCookies != 2 || expSummary.RotatingGoogleProfiles != 1 {
		t.Fatalf("unexpected export summary: %+v", expSummary)
	}

	// 验证密码错误会被拒绝，且归档外层不含明文 Cookie
	rawArchive, _ := os.ReadFile(encArchive)
	if bytes.Contains(rawArchive, []byte("dummy-sid-token-123")) {
		t.Fatal("encrypted archive leaked plaintext cookie value")
	}
	if _, _, err := openSessionArchivePayload(encArchive, "WrongPass"); err == nil {
		t.Fatal("expected wrong password error, got nil")
	}

	// 2. 测试导入到「已有实例（按名称匹配，不同 profile_id）」且验证复用目标 DPAPI 密钥、不改目标 app.db、不碰 Preferences
	targetExisting := AppProfile{
		ProfileID:       "22222222-2222-4222-8222-222222222222",
		ProfileName:     "Google 主号",
		UserDataDir:     "22222222-2222-4222-8222-222222222222",
		FingerprintArgs: []string{"--fingerprint=11111111"},
	}
	targetRootExisting := createTestAppRoot(t, []AppProfile{targetExisting})
	targetExistingDir := filepath.Join(targetRootExisting, "data", targetExisting.ProfileID)

	// 先在目标机生成一个独立 DPAPI 密钥与一条其他域名 Cookie + 目标机专属 Preferences
	targetSeedKey, _, err := ensureTargetLocalStateDPAPIKey(targetExistingDir)
	if err != nil {
		t.Fatalf("seed target key: %v", err)
	}
	if _, _, err := importProfileCookies(targetExistingDir, ProfileCookieDump{
		SchemaVersion: cookieDBVersionCurrent,
		ProfileID:     targetExisting.ProfileID,
		ProfileName:   targetExisting.ProfileName,
		Cookies: []PortableCookieRecord{
			{
				CreationUTC:  13360000000000000,
				HostKey:      ".other.example",
				Name:         "old_cookie",
				Value:        "keep-on-merge",
				Path:         "/",
				ExpiresUTC:   13450000000000000,
				HasExpires:   1,
				IsPersistent: 1,
				SourceScheme: 2,
				SourcePort:   443,
			},
		},
	}, "replace", ""); err != nil {
		t.Fatalf("seed target cookie: %v", err)
	}
	_ = os.MkdirAll(filepath.Join(targetExistingDir, "Default"), 0o755)
	_ = os.WriteFile(filepath.Join(targetExistingDir, "Default", "Preferences"), []byte(`{"marker":"target-untouched"}`), 0o644)

	// 先用 merge 模式导入，确认原 other.example Cookie 被保留、Google Cookie 被写入、目标密钥被复用
	impMerge, err := runImport(ImportOptions{
		AppRoot:    targetRootExisting,
		InputPath:  encArchive,
		Password:   "TestPass123!",
		MatchBy:    "id-or-name",
		CookieMode: "merge",
		Force:      true,
	})
	if err != nil {
		t.Fatalf("runImport (merge) failed: %v", err)
	}
	if impMerge.MatchedCount != 1 || impMerge.CreatedCount != 0 || impMerge.TotalCookiesWritten != 3 || impMerge.FingerprintDiffCount != 1 {
		t.Fatalf("unexpected merge import summary: %+v", impMerge)
	}
	if impMerge.BackupRoot == "" || !dirExists(impMerge.BackupRoot) {
		t.Fatalf("expected backup dir to be created, got %q", impMerge.BackupRoot)
	}

	// 验证目标密钥与导入前完全相同（复用了目标机的 DPAPI key）
	afterKeyInfo, err := readLocalStateDPAPIKey(targetExistingDir)
	if err != nil || !bytes.Equal(afterKeyInfo.AESKey, targetSeedKey) {
		t.Fatalf("expected target DPAPI key to be reused")
	}

	// 验证目标机 Preferences 未被覆盖
	prefBytes, _ := os.ReadFile(filepath.Join(targetExistingDir, "Default", "Preferences"))
	if !strings.Contains(string(prefBytes), "target-untouched") {
		t.Fatalf("target Preferences was modified unexpectedly: %s", string(prefBytes))
	}

	// 验证目标机 Local Storage / Session Storage 已恢复且 LOCK 未写入
	if b, err := os.ReadFile(filepath.Join(targetExistingDir, "Default", "Local Storage", "leveldb", "000003.log")); err != nil || string(b) != "ls-token-payload" {
		t.Fatalf("Local Storage mismatch: %v / %q", err, string(b))
	}
	if fileExists(filepath.Join(targetExistingDir, "Default", "Local Storage", "leveldb", "LOCK")) {
		t.Fatal("transient LOCK file should not be copied into target")
	}
	if b, err := os.ReadFile(filepath.Join(targetExistingDir, "Default", "Session Storage", "000001.ldb")); err != nil || string(b) != "ss-token-payload" {
		t.Fatalf("Session Storage mismatch: %v / %q", err, string(b))
	}

	// 3. 测试不加密导出 + 导入到全新空目标机（--create-missing）
	plainArchive := filepath.Join(t.TempDir(), "sessions-plain.antsess")
	if _, err := runExport(ExportOptions{
		AppRoot:               srcRoot,
		OutputPath:            plainArchive,
		NoPassword:            true,
		IncludeLocalStorage:   true,
		IncludeSessionStorage: true,
	}); err != nil {
		t.Fatalf("runExport (no-password) failed: %v", err)
	}

	emptyTargetRoot := createTestAppRoot(t, nil)

	// 不加 --create-missing 时应跳过且不写入 app.db
	skipSummary, err := runImport(ImportOptions{
		AppRoot:   emptyTargetRoot,
		InputPath: plainArchive,
		Force:     true,
	})
	if err != nil {
		t.Fatalf("runImport (empty without create-missing) failed: %v", err)
	}
	if skipSummary.SkippedCount != 1 || skipSummary.CreatedCount != 0 {
		t.Fatalf("expected 1 skipped and 0 created, got %+v", skipSummary)
	}

	// 加 --create-missing（不加 --sync-fingerprint）应创建最小空壳实例（代理和指纹均为空）
	createSummary, err := runImport(ImportOptions{
		AppRoot:       emptyTargetRoot,
		InputPath:     plainArchive,
		CreateMissing: true,
		CookieMode:    "replace",
		Force:         true,
	})
	if err != nil {
		t.Fatalf("runImport (create-missing) failed: %v", err)
	}
	if createSummary.CreatedCount != 1 || createSummary.TotalCookiesWritten != 2 {
		t.Fatalf("unexpected create-missing summary: %+v", createSummary)
	}

	// 校验新建实例的 DB 记录和 NetworkDataMigrated 标记 + Cookies 可重新解密还原
	instEmpty, err := resolveAppInstallation(emptyTargetRoot)
	if err != nil {
		t.Fatalf("resolve empty target: %v", err)
	}
	newProfiles, err := loadProfilesFromDB(instEmpty, false)
	if err != nil || len(newProfiles) != 1 {
		t.Fatalf("expected 1 created profile in app.db, got %d (err=%v)", len(newProfiles), err)
	}
	if newProfiles[0].ProfileID != srcProfile.ProfileID || newProfiles[0].ProfileName != srcProfile.ProfileName {
		t.Fatalf("created shell profile mismatch: %+v", newProfiles[0])
	}
	if len(newProfiles[0].FingerprintArgs) != 0 {
		t.Fatalf("expected empty fingerprint_args by default, got %v", newProfiles[0].FingerprintArgs)
	}
	if !fileExists(filepath.Join(newProfiles[0].ResolvedDataDir, "Default", "Network", "NetworkDataMigrated")) {
		t.Fatal("missing NetworkDataMigrated checkpoint marker")
	}

	reRead, err := exportProfileCookies(newProfiles[0])
	if err != nil {
		t.Fatalf("re-read imported cookies failed: %v", err)
	}
	if len(reRead.Dump.Cookies) != 2 || reRead.Dump.Cookies[0].Value != "dummy-sid-token-123" || reRead.Dump.Cookies[1].Value != "dummy-rotating-token-xyz" {
		t.Fatalf("re-decrypted cookies mismatch: %+v", reRead.Dump.Cookies)
	}
}

// TestDBSCAndV20Detection 验证对 Device Bound Sessions (DBSC) 硬件会话表与 v20 App-Bound Cookie 的识别告警能力。
func TestDBSCAndV20Detection(t *testing.T) {
	dir := t.TempDir()
	netDir := filepath.Join(dir, "Default", "Network")
	_ = os.MkdirAll(netDir, 0o755)

	// 构造含 1 行数据的 Device Bound Sessions 库
	dbscDB, err := sql.Open("sqlite", filepath.Join(netDir, "Device Bound Sessions"))
	if err != nil {
		t.Fatalf("open dbsc: %v", err)
	}
	_, err = dbscDB.Exec(`CREATE TABLE dbsc_session_tbl(key TEXT, proto BLOB); INSERT INTO dbsc_session_tbl VALUES ('k1', X'0102');`)
	dbscDB.Close()
	if err != nil {
		t.Fatalf("seed dbsc: %v", err)
	}

	// 构造含 1 条 v20 Cookie 的 Cookies 库
	ckDB, err := sql.Open("sqlite", filepath.Join(netDir, "Cookies"))
	if err != nil {
		t.Fatalf("open cookies: %v", err)
	}
	_, err = ckDB.Exec(`
		CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
		INSERT INTO meta VALUES ('version', '24');
		CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL,source_type INTEGER NOT NULL,has_cross_site_ancestor INTEGER NOT NULL);
		INSERT INTO cookies VALUES (1, '.google.com', '', 'SID', '', X'7632300102030405060708090a0b0c0d0e0f10', '/', 2, 1, 1, 1, 1, 1, 2, 0, 2, 443, 1, 1, 0);
	`)
	ckDB.Close()
	if err != nil {
		t.Fatalf("seed v20 cookies: %v", err)
	}

	res, err := exportProfileCookies(AppProfile{
		ProfileID:       "p-detect",
		ProfileName:     "detect",
		ResolvedDataDir: dir,
	})
	if err != nil {
		t.Fatalf("exportProfileCookies failed: %v", err)
	}
	if res.DBSCSessionCount != 1 {
		t.Fatalf("expected DBSCSessionCount=1, got %d", res.DBSCSessionCount)
	}
	if res.V20CookieCount != 1 {
		t.Fatalf("expected V20CookieCount=1, got %d", res.V20CookieCount)
	}
	if len(res.Warnings) < 2 {
		t.Fatalf("expected warnings for DBSC and v20, got %v", res.Warnings)
	}
}

// TestRealChromium144LoadsImportedCookies 使用仓库内的真实 Chromium 144 内核离线验证（about:blank + --no-proxy-server，零外网访问）：
// 证明本工具生成的 Local State + Default/Network/Cookies 可被真实 Chromium 144 完整解密并识别。
func TestRealChromium144LoadsImportedCookies(t *testing.T) {
	chromeExe := filepath.Join("..", "..", "chrome", "chromium-144.0.7559.132", "chrome.exe")
	if !fileExists(chromeExe) {
		t.Skip("未发现本地 chromium-144.0.7559.132/chrome.exe，跳过真实内核集成测试")
	}
	absChrome, _ := filepath.Abs(chromeExe)

	profileDir := t.TempDir()
	futureChromeMicros := (time.Now().Add(30*24*time.Hour).Unix() + 11644473600) * 1_000_000
	nowChromeMicros := (time.Now().Unix() + 11644473600) * 1_000_000

	expectedVal := "ant_migrator_real_chromium144_ok_987654"
	if _, _, err := importProfileCookies(profileDir, ProfileCookieDump{
		SchemaVersion: cookieDBVersionCurrent,
		ProfileID:     "real-chrome-test",
		ProfileName:   "real-chrome-test",
		Cookies: []PortableCookieRecord{
			{
				CreationUTC:          nowChromeMicros,
				HostKey:              ".example.test",
				TopFrameSiteKey:      "",
				Name:                 "__Secure-TEST_SESSION",
				Value:                expectedVal,
				Path:                 "/",
				ExpiresUTC:           futureChromeMicros,
				IsSecure:             1,
				IsHTTPOnly:           1,
				LastAccessUTC:        nowChromeMicros,
				HasExpires:           1,
				IsPersistent:         1,
				Priority:             2,
				SameSite:             1,
				SourceScheme:         2,
				SourcePort:           443,
				LastUpdateUTC:        nowChromeMicros,
				SourceType:           1,
				HasCrossSiteAncestor: 0,
			},
		},
	}, "replace", ""); err != nil {
		t.Fatalf("importProfileCookies failed: %v", err)
	}

	// 找一个本地空闲调试端口
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cmd := exec.Command(absChrome,
		fmt.Sprintf("--user-data-dir=%s", profileDir),
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--headless=new",
		"--no-first-run",
		"--disable-sync",
		"--no-proxy-server",
		"--disable-gpu",
		"about:blank",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start chromium: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	wsURL, err := waitForCDPBrowserWS(port, 12*time.Second)
	if err != nil {
		t.Fatalf("CDP not ready: %v", err)
	}

	// 验证运行时进程占用检测能准确识别运行中的 Chromium 144
	if inUse, rel := checkProfileDirInUse(profileDir); !inUse {
		t.Fatalf("expected checkProfileDirInUse=true while Chromium 144 is running")
	} else if rel == "" {
		t.Fatal("expected non-empty locked file relative path")
	}

	respJSON, err := callCDPStorageGetCookies(wsURL)
	if err != nil {
		t.Fatalf("CDP Storage.getCookies failed: %v", err)
	}
	if !strings.Contains(respJSON, expectedVal) || !strings.Contains(respJSON, "__Secure-TEST_SESSION") {
		t.Fatalf("Chromium 144 did not return expected decrypted cookie! CDP response: %s", respJSON)
	}

	// 停止进程并确认锁已释放
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if inUse, _ := checkProfileDirInUse(profileDir); !inUse {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("expected checkProfileDirInUse=false after Chromium 144 exited")
}

// TestOptionalProxyAndFingerprintMigration 验证可选「核心指纹」与「最小代理节点/虚拟分组」迁移：
// 包含确定性指纹种子物化、按 proxy_config 去重复用、ID 冲突自动改号保护及隔离未引用节点。
func TestOptionalProxyAndFingerprintMigration(t *testing.T) {
	// 源端包含两个实例：
	// p1: 绑定普通代理池节点（且未显式配置 --fingerprint= 种子，测试确定性种子物化）
	// p2: 绑定虚拟代理分组（含成员节点），且带有显式 --fingerprint= 种子
	// 同时源代理池里放一个「未被引用的多余节点」，验证不会污染迁移包
	p1 := AppProfile{
		ProfileID:       "aaaa1111-1111-4111-8111-111111111111",
		ProfileName:     "Google-A",
		UserDataDir:     "aaaa1111-1111-4111-8111-111111111111",
		FingerprintArgs: []string{"--fingerprint-brand=Chrome", "--lang=en-US", "--timezone=America/Los_Angeles"},
		ProxyMode:       "fixed",
		ProxyID:         "proxy-us-1",
		ProxyConfig:     "socks5://userA:secretPassA@203.0.113.10:1080",
		ProxyBindName:   "US-Residential-1",
	}
	p2 := AppProfile{
		ProfileID:       "bbbb2222-2222-4222-8222-222222222222",
		ProfileName:     "Google-B",
		UserDataDir:     "bbbb2222-2222-4222-8222-222222222222",
		FingerprintArgs: []string{"--fingerprint=55667788", "--lang=ja-JP", "--timezone=Asia/Tokyo"},
		ProxyMode:       "fixed",
		ProxyID:         "vgroup-jp",
		ProxyBindName:   "JP-Pool",
	}
	srcRoot := createTestAppRoot(t, []AppProfile{p1, p2})

	// 在源 app.db 注入代理池节点（含订阅 URL 与测速缓存，验证不迁移这些垃圾字段）与虚拟分组
	srcDB, err := sql.Open("sqlite", filepath.Join(srcRoot, "data", "app.db"))
	if err != nil {
		t.Fatalf("open src db: %v", err)
	}
	_, err = srcDB.Exec(`
		INSERT INTO browser_proxies (proxy_id, proxy_name, proxy_config, preferred_kernel, dns_servers, group_name, source_url, last_latency_ms, sort_order) VALUES
			('proxy-us-1', 'US-Residential-1', 'socks5://userA:secretPassA@203.0.113.10:1080', 'xray', '1.1.1.1', 'US', 'https://secret-sub.example/sub', 120, 1),
			('proxy-jp-1', 'JP-Node-1', 'hysteria2://secretTok@198.51.100.20:443?sni=example.com', 'sing-box', '', 'JP', 'https://secret-sub.example/jp', 85, 2),
			('proxy-unused', 'Unused-Node', 'socks5://unused:unused@192.0.2.99:9999', 'xray', '', 'Unused', '', 50, 3);
		INSERT INTO browser_proxy_virtual_groups (group_id, group_name, strategy, member_proxy_ids, member_group_names) VALUES
			('vgroup-jp', 'JP-Pool', 'round_robin', '["proxy-jp-1"]', '[]');
	`)
	srcDB.Close()
	if err != nil {
		t.Fatalf("seed src proxies: %v", err)
	}

	// 写入测试 Cookie
	for _, p := range []AppProfile{p1, p2} {
		dir := filepath.Join(srcRoot, "data", p.ProfileID)
		if _, _, err := importProfileCookies(dir, ProfileCookieDump{
			SchemaVersion: cookieDBVersionCurrent,
			ProfileID:     p.ProfileID,
			ProfileName:   p.ProfileName,
			Cookies: []PortableCookieRecord{{
				CreationUTC: 13370000000000000, HostKey: ".google.com", Name: "SID", Value: "sid-" + p.ProfileName,
				Path: "/", ExpiresUTC: 13450000000000000, IsSecure: 1, IsHTTPOnly: 1, HasExpires: 1, IsPersistent: 1, SourceScheme: 2, SourcePort: 443,
			}},
		}, "replace", ""); err != nil {
			t.Fatalf("seed cookie %s: %v", p.ProfileName, err)
		}
	}

	// 1. 先导出纯登录态包，验证 --sync-proxy / --sync-fingerprint 会明确报错提醒
	loginOnlyPath := filepath.Join(t.TempDir(), "login-only.antsess")
	if _, err := runExport(ExportOptions{
		AppRoot:               srcRoot,
		OutputPath:            loginOnlyPath,
		Password:              "StrongPass99!",
		IncludeLocalStorage:   true,
		IncludeSessionStorage: true,
	}); err != nil {
		t.Fatalf("export login-only: %v", err)
	}
	emptyCheckRoot := createTestAppRoot(t, nil)
	if _, err := runImport(ImportOptions{
		AppRoot: emptyCheckRoot, InputPath: loginOnlyPath, Password: "StrongPass99!", SyncProxy: true, Force: true,
	}); err == nil {
		t.Fatal("expected error when --sync-proxy is used on archive without proxy data")
	}
	if _, err := runImport(ImportOptions{
		AppRoot: emptyCheckRoot, InputPath: loginOnlyPath, Password: "StrongPass99!", SyncFingerprint: true, Force: true,
	}); err == nil {
		t.Fatal("expected error when --sync-fingerprint is used on archive without fingerprint data")
	}

	// 2. 导出带「核心指纹 + 代理 IP」的加密迁移包
	fullArchive := filepath.Join(t.TempDir(), "with-proxy-fp.antsess")
	expSum, err := runExport(ExportOptions{
		AppRoot:               srcRoot,
		OutputPath:            fullArchive,
		Password:              "StrongPass99!",
		IncludeLocalStorage:   true,
		IncludeSessionStorage: true,
		IncludeFingerprint:    true,
		IncludeProxy:          true,
	})
	if err != nil {
		t.Fatalf("export with proxy+fp failed: %v", err)
	}
	if expSum.ExportedFingerprints != 2 || expSum.ExportedProxies != 2 {
		t.Fatalf("unexpected export summary: %+v", expSum)
	}

	// 安全性检查：确认公开 manifest.json 与加密外层归档绝不泄露代理 IP/密码/订阅链接/未引用节点/原始指纹参数
	rawZipBytes, _ := os.ReadFile(fullArchive)
	for _, sensitive := range []string{"secretPassA", "203.0.113.10", "secretTok", "198.51.100.20", "secret-sub.example", "proxy-unused", "192.0.2.99", "America/Los_Angeles", "55667788"} {
		if bytes.Contains(rawZipBytes, []byte(sensitive)) {
			t.Fatalf("encrypted archive or manifest leaked sensitive token %q", sensitive)
		}
	}
	manifest, err := readArchiveManifest(fullArchive)
	if err != nil {
		t.Fatalf("readArchiveManifest: %v", err)
	}
	if !manifest.IncludeFingerprint || !manifest.IncludeProxy {
		t.Fatalf("manifest missing IncludeFingerprint/IncludeProxy flags: %+v", manifest)
	}

	// 3. 测试导入到「已有实例」（按名称匹配，不同 profile_id；同时模拟目标代理池冲突：
	//    目标机已有同名 ID 'proxy-us-1' 但配置不同，验证绝不覆写目标机无关节点！）
	targetExistingP1 := AppProfile{
		ProfileID:       "cccc3333-3333-4333-8333-333333333333",
		ProfileName:     "Google-A",
		UserDataDir:     "cccc3333-3333-4333-8333-333333333333",
		FingerprintArgs: []string{"--fingerprint=111111"},
	}
	targetExistingRoot := createTestAppRoot(t, []AppProfile{targetExistingP1})
	targetExistingDB, _ := sql.Open("sqlite", filepath.Join(targetExistingRoot, "data", "app.db"))
	_, err = targetExistingDB.Exec(`
		UPDATE browser_profiles SET tags = '["keep-tag"]', launch_args = '["--keep-arg"]' WHERE profile_id = ?;
		INSERT INTO browser_proxies (proxy_id, proxy_name, proxy_config, sort_order) VALUES
			('proxy-us-1', 'US-Residential-1', 'socks5://different:node@198.51.100.99:7777', 1);
	`, targetExistingP1.ProfileID)
	targetExistingDB.Close()
	if err != nil {
		t.Fatalf("seed target conflict proxy: %v", err)
	}

	impExist, err := runImport(ImportOptions{
		AppRoot:         targetExistingRoot,
		InputPath:       fullArchive,
		Password:        "StrongPass99!",
		ProfileFilters:  []string{"Google-A"},
		SyncFingerprint: true,
		SyncProxy:       true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("import to existing with proxy+fp failed: %v", err)
	}
	if impExist.MatchedCount != 1 || impExist.FingerprintsSynced != 1 || impExist.ProxiesBound != 1 || impExist.ProxyNodesInserted != 1 || impExist.ProxyNodesReused != 0 {
		t.Fatalf("unexpected existing import summary: %+v", impExist)
	}
	// 验证自动备份了目标 app.db
	if impExist.BackupRoot == "" || !fileExists(filepath.Join(impExist.BackupRoot, "app.db")) {
		t.Fatalf("expected target app.db backup inside %q", impExist.BackupRoot)
	}

	// 检查目标 DB：原冲突节点 proxy-us-1 未被覆盖，新节点已创建，实例已正确绑定且 tags/launch_args 未被改动，且确定性指纹种子已物化
	verifyDB, _ := sql.Open("sqlite", filepath.Join(targetExistingRoot, "data", "app.db"))
	defer verifyDB.Close()
	var oldCfg string
	if err := verifyDB.QueryRow(`SELECT proxy_config FROM browser_proxies WHERE proxy_id = 'proxy-us-1'`).Scan(&oldCfg); err != nil || oldCfg != "socks5://different:node@198.51.100.99:7777" {
		t.Fatalf("existing unrelated target proxy was overwritten! got=%q err=%v", oldCfg, err)
	}
	var gotProxyID, gotProxyCfg, gotFP, gotTags, gotLaunch, gotKernel, gotSubURL string
	if err := verifyDB.QueryRow(`SELECT proxy_id, proxy_config, fingerprint_args, tags, launch_args FROM browser_profiles WHERE profile_id = ?`, targetExistingP1.ProfileID).
		Scan(&gotProxyID, &gotProxyCfg, &gotFP, &gotTags, &gotLaunch); err != nil {
		t.Fatalf("query updated target profile: %v", err)
	}
	if gotProxyID == "proxy-us-1" || gotProxyCfg != "socks5://userA:secretPassA@203.0.113.10:1080" {
		t.Fatalf("unexpected target profile proxy binding: id=%q cfg=%q", gotProxyID, gotProxyCfg)
	}
	if err := verifyDB.QueryRow(`SELECT preferred_kernel, source_url FROM browser_proxies WHERE proxy_id = ?`, gotProxyID).Scan(&gotKernel, &gotSubURL); err != nil {
		t.Fatalf("query migrated proxy node: %v", err)
	}
	if gotKernel != "xray" || gotSubURL != "" {
		t.Fatalf("expected preferred_kernel=xray and empty source_url, got kernel=%q sub=%q", gotKernel, gotSubURL)
	}
	expectedSeedArg := fmt.Sprintf("--fingerprint=%d", deriveFingerprintSeedFromProfileID(p1.ProfileID))
	if !strings.Contains(gotFP, expectedSeedArg) || !strings.Contains(gotFP, "--timezone=America/Los_Angeles") {
		t.Fatalf("expected materialized fingerprint seed %q and timezone in %s", expectedSeedArg, gotFP)
	}
	if gotTags != `["keep-tag"]` || gotLaunch != `["--keep-arg"]` {
		t.Fatalf("unrelated profile fields were altered: tags=%s launch=%s", gotTags, gotLaunch)
	}

	// 再次导入同一个包到同一目标：验证按 proxy_config 自动去重复用，不产生重复节点
	impReuse, err := runImport(ImportOptions{
		AppRoot:         targetExistingRoot,
		InputPath:       fullArchive,
		Password:        "StrongPass99!",
		ProfileFilters:  []string{"Google-A"},
		SyncFingerprint: true,
		SyncProxy:       true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("second import for dedup failed: %v", err)
	}
	if impReuse.ProxyNodesReused != 1 || impReuse.ProxyNodesInserted != 0 {
		t.Fatalf("expected proxy node reuse on second import, got reused=%d inserted=%d", impReuse.ProxyNodesReused, impReuse.ProxyNodesInserted)
	}

	// 4. 测试全新空目标机一步导入（--create-missing --sync-fingerprint --sync-proxy，含普通代理节点 + 虚拟代理分组 + sing-box 协议节点）
	emptyRoot := createTestAppRoot(t, nil)
	impEmpty, err := runImport(ImportOptions{
		AppRoot:         emptyRoot,
		InputPath:       fullArchive,
		Password:        "StrongPass99!",
		CreateMissing:   true,
		SyncFingerprint: true,
		SyncProxy:       true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("import to empty target failed: %v", err)
	}
	if impEmpty.CreatedCount != 2 || impEmpty.FingerprintsSynced != 2 || impEmpty.ProxiesBound != 2 || impEmpty.ProxyNodesInserted != 2 || impEmpty.VirtualGroupsSynced != 1 {
		t.Fatalf("unexpected empty target import summary: %+v", impEmpty)
	}

	// 验证虚拟分组与 sing-box 成员节点都被干净写入，且未引用节点未出现
	emptyDB, _ := sql.Open("sqlite", filepath.Join(emptyRoot, "data", "app.db"))
	defer emptyDB.Close()
	var proxyCount, vgCount int
	_ = emptyDB.QueryRow(`SELECT COUNT(*) FROM browser_proxies`).Scan(&proxyCount)
	_ = emptyDB.QueryRow(`SELECT COUNT(*) FROM browser_proxy_virtual_groups`).Scan(&vgCount)
	if proxyCount != 2 || vgCount != 1 {
		t.Fatalf("expected 2 proxies and 1 virtual group in empty target, got proxies=%d vgroups=%d", proxyCount, vgCount)
	}
	var jpKernel string
	if err := emptyDB.QueryRow(`SELECT preferred_kernel FROM browser_proxies WHERE proxy_id = 'proxy-jp-1'`).Scan(&jpKernel); err != nil || jpKernel != "sing-box" {
		t.Fatalf("expected JP node preferred_kernel=sing-box, got %q (err=%v)", jpKernel, err)
	}
}

// TestMacOSCipherAndCrossOSMigrationRoundTrip 验证 macOS Chromium os_crypt_mac.mm 加密规范
// （PBKDF2-HMAC-SHA1, salt="saltysalt", iter=1003, AES-128-CBC, IV=16空格, PKCS#7, v24 SHA256(host_key)）
// 并完成 Windows DPAPI (AES-256-GCM) <-> macOS Keychain (AES-128-CBC) 完整跨系统 Cookies SQLite 往返测试。
func TestMacOSCipherAndCrossOSMigrationRoundTrip(t *testing.T) {
	// 1. 校验标准 Chromium macOS PBKDF2 派生密钥长度与确定性
	kPeanuts := deriveMacOSCookieKey("peanuts")
	if len(kPeanuts) != 16 {
		t.Fatalf("expected 16-byte AES-128 key, got %d", len(kPeanuts))
	}
	// Chromium macOS 已知向量：PBKDF2-HMAC-SHA1("peanuts", "saltysalt", 1003, 16) = d9a09d499b4e1b7461f28e67972c6dbd
	if gotHex := fmt.Sprintf("%x", kPeanuts); gotHex != "d9a09d499b4e1b7461f28e67972c6dbd" {
		t.Fatalf("macOS PBKDF2 key mismatch: got %s want d9a09d499b4e1b7461f28e67972c6dbd", gotHex)
	}

	macSecret := "dGVzdC1tYWNvcy1rZXljaGFpbg=="
	macCipher, err := newMacOSCBCCookieCipher(macSecret, "")
	if err != nil {
		t.Fatalf("newMacOSCBCCookieCipher: %v", err)
	}
	defer macCipher.Close()

	// 2. 边界长度测试（0, 1, 15, 16, 17, 32, 多块 UTF-8）
	edgeValues := []string{
		"",
		"a",
		strings.Repeat("x", 15),
		strings.Repeat("y", 16),
		strings.Repeat("z", 17),
		strings.Repeat("w", 32),
		"__Secure-1PSIDTS=sidts-CjIB_中文_token_1234567890abcdef",
	}
	for _, val := range edgeValues {
		enc, err := macCipher.EncryptCookie(".google.com", val)
		if err != nil {
			t.Fatalf("macOS encrypt %q failed: %v", val, err)
		}
		if string(enc[:3]) != "v10" {
			t.Fatalf("expected v10 prefix, got %q", string(enc[:3]))
		}
		if (len(enc)-3)%16 != 0 {
			t.Fatalf("macOS AES-CBC ciphertext not 16-byte aligned: %d", len(enc)-3)
		}
		dec, hashMatched, skippedV20, unknownPrefix, err := macCipher.DecryptCookie(enc, ".google.com", 24)
		if err != nil || !hashMatched || skippedV20 || unknownPrefix || dec != val {
			t.Fatalf("macOS decrypt mismatch for %q: dec=%q matched=%v err=%v", val, dec, hashMatched, err)
		}
		// 域名不匹配时应报告 hashMatched=false
		_, wrongHostMatched, _, _, err := macCipher.DecryptCookie(enc, ".evil.example", 24)
		if err != nil || wrongHostMatched {
			t.Fatalf("expected hashMatched=false for wrong host, got matched=%v err=%v", wrongHostMatched, err)
		}
	}

	// 错误 Keychain 密钥应触发解密失败或哈希不匹配
	wrongMacCipher, _ := newMacOSCBCCookieCipher("wrong-keychain-secret", "")
	defer wrongMacCipher.Close()
	sampleEnc, _ := macCipher.EncryptCookie(".google.com", "super-secret-sid-value")
	if _, matched, _, _, err := wrongMacCipher.DecryptCookie(sampleEnc, ".google.com", 24); err == nil && matched {
		t.Fatal("wrong macOS keychain secret unexpectedly succeeded with v24 hash match")
	}

	// 3. 完整跨系统往返：Windows DPAPI 写入 -> Windows 导出明文 -> macOS AES-128-CBC 写入 SQLite -> macOS 解密导出 -> Windows DPAPI 回写验证
	winDir := t.TempDir()
	origCookies := []PortableCookieRecord{
		{
			CreationUTC: 13370000000000000, HostKey: ".google.com", Name: "SID", Value: "win-to-mac-sid-001",
			Path: "/", ExpiresUTC: 13450000000000000, IsSecure: 1, IsHTTPOnly: 1, HasExpires: 1, IsPersistent: 1,
			Priority: 2, SameSite: -1, SourceScheme: 2, SourcePort: 443, SourceType: 1,
		},
		{
			CreationUTC: 13370000000000001, HostKey: "accounts.google.com", Name: "__Host-GAPS", Value: "1:gaps-token-xyz",
			Path: "/", ExpiresUTC: 13450000000000000, IsSecure: 1, IsHTTPOnly: 1, HasExpires: 1, IsPersistent: 1,
			Priority: 2, SameSite: 0, SourceScheme: 2, SourcePort: 443, SourceType: 1,
		},
	}
	if _, _, err := importProfileCookies(winDir, ProfileCookieDump{
		SchemaVersion: cookieDBVersionCurrent, ProfileID: "cross-os", ProfileName: "cross-os", Cookies: origCookies,
	}, "replace", ""); err != nil {
		t.Fatalf("Windows seed failed: %v", err)
	}
	fromWin, err := exportProfileCookies(AppProfile{ProfileID: "cross-os", ProfileName: "cross-os", ResolvedDataDir: winDir})
	if err != nil {
		t.Fatalf("Windows export failed: %v", err)
	}

	// 写入模拟的 macOS 目标目录（使用 macOS Keychain AES-128-CBC cipher）
	macDir := t.TempDir()
	written, err := importProfileCookiesWithCipher(macDir, macCipher, fromWin.Dump, "replace", "")
	if err != nil || written != 2 {
		t.Fatalf("macOS import failed: written=%d err=%v", written, err)
	}
	if !fileExists(filepath.Join(macDir, "Default", "Network", "NetworkDataMigrated")) {
		t.Fatal("missing NetworkDataMigrated marker in macOS target dir")
	}
	// macOS 不应生成 Windows DPAPI Local State
	if fileExists(filepath.Join(macDir, "Local State")) {
		t.Fatal("macOS import should not create Windows DPAPI Local State")
	}

	// 从 macOS 目录用 macOS cipher 解密读出并比对全部字段
	fromMac, err := exportProfileCookiesWithCipher(AppProfile{ProfileID: "cross-os", ProfileName: "cross-os", ResolvedDataDir: macDir}, macCipher)
	if err != nil {
		t.Fatalf("macOS export failed: %v", err)
	}
	if len(fromMac.Dump.Cookies) != 2 || fromMac.Dump.Cookies[0].Value != "win-to-mac-sid-001" || fromMac.Dump.Cookies[1].Value != "1:gaps-token-xyz" {
		t.Fatalf("macOS round-trip cookie mismatch: %+v", fromMac.Dump.Cookies)
	}
	if fromMac.GoogleCookieCount != 2 {
		t.Fatalf("expected GoogleCookieCount=2, got %d", fromMac.GoogleCookieCount)
	}
}

// waitForCDPBrowserWS 轮询本机 Chrome DevTools Protocol /json/version 端点直至返回浏览器 WebSocket 地址。
func waitForCDPBrowserWS(port int, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 800 * time.Millisecond}
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", port)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var v struct {
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			if json.Unmarshal(body, &v) == nil && v.WebSocketDebuggerURL != "" {
				return v.WebSocketDebuggerURL, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return "", fmt.Errorf("timeout waiting for %s", url)
}

// callCDPStorageGetCookies 使用纯标准库实现最小 RFC6455 WebSocket 文本帧调用 Storage.getCookies。
func callCDPStorageGetCookies(wsURL string) (string, error) {
	stripped := strings.TrimPrefix(wsURL, "ws://")
	slashIdx := strings.Index(stripped, "/")
	if slashIdx < 0 {
		return "", fmt.Errorf("invalid wsURL: %s", wsURL)
	}
	hostPort := stripped[:slashIdx]
	path := stripped[slashIdx:]

	conn, err := net.DialTimeout("tcp", hostPort, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	secKey := base64.StdEncoding.EncodeToString(keyBytes[:])
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, hostPort, secKey)
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		return "", fmt.Errorf("ws upgrade failed: %q err=%v", statusLine, err)
	}
	expectedAccept := computeWSAccept(secKey)
	gotAccept := ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		if line == "\r\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
			gotAccept = strings.TrimSpace(line[len("sec-websocket-accept:"):])
		}
	}
	if gotAccept != expectedAccept {
		return "", fmt.Errorf("ws accept mismatch")
	}

	payload := []byte(`{"id":1,"method":"Storage.getCookies"}`)
	if err := writeMaskedWSTextFrame(conn, payload); err != nil {
		return "", err
	}
	return readWSTextFrame(br)
}

// computeWSAccept 按 RFC 6455 计算 WebSocket 握手响应头 Sec-WebSocket-Accept。
func computeWSAccept(secKey string) string {
	h := sha1.Sum([]byte(secKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// writeMaskedWSTextFrame 构造并写入带随机掩码的 RFC 6455 客户端文本帧。
func writeMaskedWSTextFrame(w io.Writer, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x81) // FIN + text frame
	n := len(payload)
	switch {
	case n <= 125:
		hdr = append(hdr, byte(0x80|n))
	case n <= 65535:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		hdr = append(hdr, 0x80|127)
		hdr = append(hdr, b[:]...)
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)

	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

// readWSTextFrame 读取并解码单条 RFC 6455 服务端 WebSocket 文本帧。
func readWSTextFrame(br *bufio.Reader) (string, error) {
	b1, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	b2, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	_ = b1
	masked := (b2 & 0x80) != 0
	length := uint64(b2 & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return "", err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(br, ext[:]); err != nil {
			return "", err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(br, maskKey[:]); err != nil {
			return "", err
		}
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(br, data); err != nil {
		return "", err
	}
	if masked {
		for i := range data {
			data[i] ^= maskKey[i%4]
		}
	}
	return string(data), nil
}
