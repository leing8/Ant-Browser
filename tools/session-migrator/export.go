package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const toolVersion = "1.1.0"

type ExportOptions struct {
	AppRoot               string
	OutputPath            string
	Password              string
	NoPassword            bool
	ProfileFilters        []string
	IncludeLocalStorage   bool
	IncludeSessionStorage bool
	IncludeIndexedDB      bool
	IncludeFingerprint    bool
	IncludeProxy          bool
	IncludeDeleted        bool
	SkipLocked            bool
	SkipUnreadable        bool
}

type ExportSummary struct {
	OutputPath              string
	ArchiveSizeBytes        int64
	Encrypted               bool
	ExportedProfiles        int
	SkippedLockedProfiles   int
	SkippedUnreadable       int
	TotalCookies            int
	TotalGoogleCookies      int
	ExportedFingerprints    int
	ExportedProxies         int
	RotatingGoogleProfiles  int
	V20Profiles             int
	DBSCProfiles            int
	Warnings                []string
}

func runExport(opts ExportOptions) (*ExportSummary, error) {
	if !opts.NoPassword && opts.Password == "" {
		return nil, fmt.Errorf("未提供密码；如需不加密导出请显式传 --no-password")
	}
	if opts.Password != "" && len([]rune(opts.Password)) < minPasswordRunes {
		return nil, fmt.Errorf("导出密码至少需要 %d 个字符", minPasswordRunes)
	}

	inst, err := resolveAppInstallation(opts.AppRoot)
	if err != nil {
		return nil, err
	}
	profiles, err := loadProfilesFromDB(inst, opts.IncludeDeleted)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("在 %s 中未找到可导出的实例", inst.DBPath)
	}

	selected, missingFilters := filterProfiles(profiles, opts.ProfileFilters)
	if len(missingFilters) > 0 {
		return nil, fmt.Errorf("未找到指定实例: %s", strings.Join(missingFilters, ", "))
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("筛选后没有可导出的实例")
	}

	// 若开启了可选代理迁移，按只读快照加载源机代理目录（仅导出被选中实例实际引用的节点）
	var proxyCatalog *sourceProxyCatalog
	if opts.IncludeProxy {
		proxyCatalog, err = loadSourceProxyCatalog(inst)
		if err != nil {
			return nil, fmt.Errorf("读取源代理目录失败: %w", err)
		}
	}

	// 第一步：全量前置锁检查，避免导出运行中实例导致 SQLite 未落盘或抓到陈旧的 Google PSIDTS/SIDCC
	var lockedMessages []string
	var readyProfiles []AppProfile
	for _, p := range selected {
		if dirExists(p.ResolvedDataDir) {
			if locked, lockedRel := checkProfileDirInUse(p.ResolvedDataDir); locked {
				lockedMessages = append(lockedMessages, fmt.Sprintf("实例「%s」(%s) 正在运行，文件被占用: %s", p.ProfileName, p.ProfileID, lockedRel))
				if opts.SkipLocked {
					continue
				}
			}
		}
		readyProfiles = append(readyProfiles, p)
	}
	if len(lockedMessages) > 0 && !opts.SkipLocked {
		return nil, fmt.Errorf("检测到以下实例仍在运行，请先在 Ant Browser 中停止对应实例再导出（或加 --skip-locked 跳过运行中实例）：\n  - %s",
			strings.Join(lockedMessages, "\n  - "))
	}
	if len(readyProfiles) == 0 {
		return nil, fmt.Errorf("所有目标实例都在运行中，没有可导出的实例")
	}

	outPath := strings.TrimSpace(opts.OutputPath)
	if outPath == "" {
		outPath = defaultExportFileName(time.Now())
	}
	if !strings.HasSuffix(strings.ToLower(outPath), archiveExt) && !strings.HasSuffix(strings.ToLower(outPath), ".zip") {
		outPath += archiveExt
	}
	absOutPath, err := filepath.Abs(outPath)
	if err != nil {
		return nil, fmt.Errorf("解析输出文件路径失败: %w", err)
	}

	var payloadBuf bytes.Buffer
	innerZip := zip.NewWriter(&payloadBuf)

	manifest := ArchiveManifest{
		Format:                archiveFormat,
		Version:               archiveVersion,
		ToolVersion:           toolVersion,
		ExportedAt:            time.Now().Format(time.RFC3339),
		SourcePlatform:        runtime.GOOS + "/" + runtime.GOARCH,
		IncludeLocalStorage:   opts.IncludeLocalStorage,
		IncludeSessionStorage: opts.IncludeSessionStorage,
		IncludeIndexedDB:      opts.IncludeIndexedDB,
		IncludeFingerprint:    opts.IncludeFingerprint,
		IncludeProxy:          opts.IncludeProxy,
		Profiles:              make([]ArchiveProfileMetadata, 0, len(readyProfiles)),
	}
	summary := &ExportSummary{
		OutputPath:            absOutPath,
		Encrypted:             !opts.NoPassword && opts.Password != "",
		SkippedLockedProfiles: len(lockedMessages),
	}
	for _, msg := range lockedMessages {
		w := "已跳过运行中实例：" + msg
		manifest.Warnings = append(manifest.Warnings, w)
		summary.Warnings = append(summary.Warnings, w)
	}

	for idx, profile := range readyProfiles {
		fmt.Printf("[%d/%d] 离线导出实例「%s」(%s)...\n", idx+1, len(readyProfiles), profile.ProfileName, shortID(profile.ProfileID))

		cookieRes, err := exportProfileCookies(profile)
		if err != nil {
			if opts.SkipUnreadable {
				w := fmt.Sprintf("已跳过无法解密的实例「%s」(%s): %v", profile.ProfileName, shortID(profile.ProfileID), err)
				manifest.Warnings = append(manifest.Warnings, w)
				summary.Warnings = append(summary.Warnings, w)
				summary.SkippedUnreadable++
				fmt.Printf("  [跳过] %s\n", w)
				continue
			}
			_ = innerZip.Close()
			return nil, fmt.Errorf("导出实例「%s」Cookie 失败: %w（若该实例来自其他电脑导致 DPAPI 密钥失效，可加 --skip-unreadable 自动跳过）", profile.ProfileName, err)
		}

		// 1. 写入解密后的完整 Cookie 快照（含 20 列原始元数据）
		cookieJSON, err := json.Marshal(cookieRes.Dump)
		if err != nil {
			_ = innerZip.Close()
			return nil, fmt.Errorf("序列化实例「%s」Cookie 失败: %w", profile.ProfileName, err)
		}
		cw, err := innerZip.Create(fmt.Sprintf("profiles/%s/cookies.json", profile.ProfileID))
		if err != nil {
			_ = innerZip.Close()
			return nil, err
		}
		if _, err := cw.Write(cookieJSON); err != nil {
			_ = innerZip.Close()
			return nil, err
		}
		zeroBytes(cookieJSON)

		// 2. 可选写入核心指纹（保存在内层载荷中，物化确定性种子防止跨 ID 漂移）
		hasFP := false
		if opts.IncludeFingerprint {
			effectiveFP := materializeEffectiveFingerprintArgs(profile.ProfileID, profile.FingerprintArgs)
			if len(effectiveFP) > 0 {
				fpJSON, mErr := json.Marshal(PortableFingerprintDump{
					ProfileID:       profile.ProfileID,
					ProfileName:     profile.ProfileName,
					FingerprintArgs: effectiveFP,
				})
				if mErr != nil {
					_ = innerZip.Close()
					return nil, fmt.Errorf("序列化实例「%s」指纹失败: %w", profile.ProfileName, mErr)
				}
				fw, cErr := innerZip.Create(fmt.Sprintf("profiles/%s/fingerprint.json", profile.ProfileID))
				if cErr != nil {
					_ = innerZip.Close()
					return nil, cErr
				}
				if _, wErr := fw.Write(fpJSON); wErr != nil {
					_ = innerZip.Close()
					return nil, wErr
				}
				hasFP = true
				summary.ExportedFingerprints++
			}
		}

		// 3. 可选写入实例代理 IP 绑定与最小被引用节点（绝不暴露在公开 manifest.json）
		hasProxy := false
		proxySummary := ""
		if opts.IncludeProxy {
			proxyDump, pSummary := buildPortableProxyDump(profile, proxyCatalog)
			if proxyDump != nil {
				pxJSON, mErr := json.Marshal(proxyDump)
				if mErr != nil {
					_ = innerZip.Close()
					return nil, fmt.Errorf("序列化实例「%s」代理配置失败: %w", profile.ProfileName, mErr)
				}
				pw, cErr := innerZip.Create(fmt.Sprintf("profiles/%s/proxy.json", profile.ProfileID))
				if cErr != nil {
					_ = innerZip.Close()
					return nil, cErr
				}
				if _, wErr := pw.Write(pxJSON); wErr != nil {
					_ = innerZip.Close()
					return nil, wErr
				}
				zeroBytes(pxJSON)
				hasProxy = true
				proxySummary = pSummary
				summary.ExportedProxies++
			}
		}

		// 4. Web Storage
		hasLS, hasSS, hasIDB := false, false, false
		if opts.IncludeLocalStorage {
			cnt, sErr := writeProfileStorageCategoryToZip(innerZip, profile.ResolvedDataDir, profile.ProfileID, storageCatLocalStorage)
			if sErr != nil {
				_ = innerZip.Close()
				return nil, fmt.Errorf("打包实例「%s」Local Storage 失败: %w", profile.ProfileName, sErr)
			}
			hasLS = cnt > 0
		}
		if opts.IncludeSessionStorage {
			cnt, sErr := writeProfileStorageCategoryToZip(innerZip, profile.ResolvedDataDir, profile.ProfileID, storageCatSessionStorage)
			if sErr != nil {
				_ = innerZip.Close()
				return nil, fmt.Errorf("打包实例「%s」Session Storage 失败: %w", profile.ProfileName, sErr)
			}
			hasSS = cnt > 0
		}
		if opts.IncludeIndexedDB {
			cnt, sErr := writeProfileStorageCategoryToZip(innerZip, profile.ResolvedDataDir, profile.ProfileID, storageCatIndexedDB)
			if sErr != nil {
				_ = innerZip.Close()
				return nil, fmt.Errorf("打包实例「%s」IndexedDB 失败: %w", profile.ProfileName, sErr)
			}
			hasIDB = cnt > 0
		}

		for _, w := range cookieRes.Warnings {
			fullWarn := fmt.Sprintf("实例「%s」: %s", profile.ProfileName, w)
			manifest.Warnings = append(manifest.Warnings, fullWarn)
			summary.Warnings = append(summary.Warnings, fullWarn)
		}

		meta := ArchiveProfileMetadata{
			ProfileID:               profile.ProfileID,
			ProfileName:             profile.ProfileName,
			CookieCount:             len(cookieRes.Dump.Cookies),
			GoogleCookieCount:       cookieRes.GoogleCookieCount,
			HasRotatingGoogleTokens: cookieRes.HasRotatingGoogleTokens,
			V20CookieCount:          cookieRes.V20CookieCount,
			DBSCSessionCount:        cookieRes.DBSCSessionCount,
			HasLocalStorage:         hasLS,
			HasSessionStorage:       hasSS,
			HasIndexedDB:            hasIDB,
			HasFingerprint:          hasFP,
			HasProxy:                hasProxy,
			ProxySummary:            proxySummary,
			FingerprintHash:         profile.FingerprintHash,
		}
		manifest.Profiles = append(manifest.Profiles, meta)

		summary.ExportedProfiles++
		summary.TotalCookies += meta.CookieCount
		summary.TotalGoogleCookies += meta.GoogleCookieCount
		if meta.HasRotatingGoogleTokens {
			summary.RotatingGoogleProfiles++
		}
		if meta.V20CookieCount > 0 {
			summary.V20Profiles++
		}
		if meta.DBSCSessionCount > 0 {
			summary.DBSCProfiles++
		}
	}

	manifest.ProfileCount = len(manifest.Profiles)
	if manifest.ProfileCount == 0 {
		_ = innerZip.Close()
		return nil, fmt.Errorf("所有候选实例均无法导出，未生成迁移包")
	}
	if err := innerZip.Close(); err != nil {
		return nil, fmt.Errorf("封装内层载荷失败: %w", err)
	}

	effectivePass := opts.Password
	if opts.NoPassword {
		effectivePass = ""
	}
	payloadBytes := payloadBuf.Bytes()
	defer zeroBytes(payloadBytes)

	if err := writeSessionArchive(absOutPath, manifest, payloadBytes, effectivePass); err != nil {
		return nil, err
	}

	if fi, err := os.Stat(absOutPath); err == nil {
		summary.ArchiveSizeBytes = fi.Size()
	}
	return summary, nil
}

func filterProfiles(profiles []AppProfile, filters []string) (matched []AppProfile, missing []string) {
	if len(filters) == 0 {
		return profiles, nil
	}
	seen := make(map[string]bool)
	for _, raw := range filters {
		q := strings.TrimSpace(raw)
		if q == "" {
			continue
		}
		hit := false
		for _, p := range profiles {
			if strings.EqualFold(p.ProfileID, q) || strings.EqualFold(p.ProfileName, q) {
				hit = true
				if !seen[p.ProfileID] {
					seen[p.ProfileID] = true
					matched = append(matched, p)
				}
			}
		}
		if !hit {
			missing = append(missing, q)
		}
	}
	return matched, missing
}

func defaultExportFileName(now time.Time) string {
	return fmt.Sprintf("ant-sessions-%s%s", now.Format("20060102-150405"), archiveExt)
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
