package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type ImportOptions struct {
	AppRoot         string
	InputPath       string
	Password        string
	ProfileFilters  []string
	MatchBy         string // "id-or-name" (default) | "id" | "name"
	CreateMissing   bool
	SyncFingerprint bool
	SyncProxy       bool
	CookieMode      string // "replace" (default) | "merge"
	NoBackup        bool
	DryRun          bool
	Force           bool
}

type ImportPlanItem struct {
	Source                ArchiveProfileMetadata
	Action                string // "match-id" | "match-name" | "create" | "skip-unmatched" | "skip-ambiguous"
	TargetProfile         *AppProfile
	NewShellProfile       *AppProfile
	WillSyncFingerprint   bool
	WillSyncProxy         bool
	FingerprintDiff       bool
	Detail                string
}

type ImportSummary struct {
	TargetRoot             string
	TargetMode             string
	DryRun                 bool
	MatchedCount           int
	CreatedCount           int
	SkippedCount           int
	TotalCookiesWritten    int
	TotalStorageFiles      int
	FingerprintsSynced     int
	ProxiesBound           int
	ProxyNodesReused       int
	ProxyNodesInserted     int
	VirtualGroupsSynced    int
	FingerprintDiffCount   int
	RotatingGoogleProfiles int
	BackupRoot             string
	Items                  []ImportPlanItem
	Warnings               []string
}

func normalizeMatchBy(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "id-or-name", "auto":
		return "id-or-name", nil
	case "id":
		return "id", nil
	case "name":
		return "name", nil
	default:
		return "", fmt.Errorf("不支持的匹配模式: %s（支持 id-or-name / id / name）", v)
	}
}

func normalizeCookieMode(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "replace":
		return "replace", nil
	case "merge":
		return "merge", nil
	default:
		return "", fmt.Errorf("不支持的 Cookie 写入模式: %s（支持 replace / merge）", v)
	}
}

func manifestHasFingerprintData(m *ArchiveManifest) bool {
	if m == nil {
		return false
	}
	if m.IncludeFingerprint {
		return true
	}
	for _, p := range m.Profiles {
		if p.HasFingerprint || len(p.LegacyFingerprintArgs) > 0 {
			return true
		}
	}
	return false
}

func manifestHasProxyData(m *ArchiveManifest) bool {
	if m == nil {
		return false
	}
	if m.IncludeProxy {
		return true
	}
	for _, p := range m.Profiles {
		if p.HasProxy {
			return true
		}
	}
	return false
}

func planImport(inst *AppInstallation, manifest *ArchiveManifest, opts ImportOptions) ([]ImportPlanItem, []AppProfile, error) {
	allExisting, err := loadProfilesFromDB(inst, true)
	if err != nil {
		return nil, nil, err
	}

	activeByID := make(map[string]AppProfile)
	activeByName := make(map[string][]AppProfile)
	allUsedIDs := make(map[string]bool)
	activeNames := make(map[string]bool)

	for _, p := range allExisting {
		idKey := strings.ToLower(strings.TrimSpace(p.ProfileID))
		if idKey != "" {
			allUsedIDs[idKey] = true
		}
		if p.DeletedAt != "" {
			continue
		}
		activeByID[idKey] = p
		nameKey := strings.ToLower(strings.TrimSpace(p.ProfileName))
		if nameKey != "" {
			activeByName[nameKey] = append(activeByName[nameKey], p)
			activeNames[nameKey] = true
		}
	}

	filteredMeta, missingFilters := filterArchiveProfiles(manifest.Profiles, opts.ProfileFilters)
	if len(missingFilters) > 0 {
		return nil, nil, fmt.Errorf("迁移包中未找到指定实例: %s", strings.Join(missingFilters, ", "))
	}

	claimedTargets := make(map[string]string)
	items := make([]ImportPlanItem, 0, len(filteredMeta))
	var toCreate []AppProfile

	for _, src := range filteredMeta {
		item := ImportPlanItem{Source: src}
		srcIDKey := strings.ToLower(strings.TrimSpace(src.ProfileID))
		srcNameKey := strings.ToLower(strings.TrimSpace(src.ProfileName))
		srcCanSyncFP := opts.SyncFingerprint && (src.HasFingerprint || len(src.LegacyFingerprintArgs) > 0)
		srcCanSyncProxy := opts.SyncProxy && src.HasProxy

		var matched *AppProfile
		matchAction := ""

		if (opts.MatchBy == "id-or-name" || opts.MatchBy == "id") && srcIDKey != "" {
			if target, ok := activeByID[srcIDKey]; ok {
				cp := target
				matched = &cp
				matchAction = "match-id"
			}
		}
		if matched == nil && (opts.MatchBy == "id-or-name" || opts.MatchBy == "name") && srcNameKey != "" {
			hits := activeByName[srcNameKey]
			if len(hits) == 1 {
				cp := hits[0]
				matched = &cp
				matchAction = "match-name"
			} else if len(hits) > 1 {
				item.Action = "skip-ambiguous"
				item.Detail = fmt.Sprintf("目标存在 %d 个同名实例「%s」，为安全起见跳过", len(hits), src.ProfileName)
				items = append(items, item)
				continue
			}
		}

		if matched != nil {
			targetKey := strings.ToLower(matched.ProfileID)
			if prev, taken := claimedTargets[targetKey]; taken {
				item.Action = "skip-ambiguous"
				item.Detail = fmt.Sprintf("目标实例「%s」已被来源实例 %s 匹配，避免重复覆盖已跳过", matched.ProfileName, prev)
				items = append(items, item)
				continue
			}
			claimedTargets[targetKey] = src.ProfileName
			item.Action = matchAction
			item.TargetProfile = matched
			item.WillSyncFingerprint = srcCanSyncFP
			item.WillSyncProxy = srcCanSyncProxy
			if !srcCanSyncFP && src.FingerprintHash != "" && matched.FingerprintHash != "" && src.FingerprintHash != matched.FingerprintHash {
				item.FingerprintDiff = true
			}
			items = append(items, item)
			continue
		}

		if !opts.CreateMissing {
			item.Action = "skip-unmatched"
			item.Detail = "目标程序无对应实例（默认不改 app.db；如需自动建空壳实例请加 --create-missing）"
			items = append(items, item)
			continue
		}

		newID := strings.TrimSpace(src.ProfileID)
		if newID == "" || allUsedIDs[strings.ToLower(newID)] {
			for {
				candidate := newRandomUUIDv4()
				if !allUsedIDs[strings.ToLower(candidate)] {
					newID = candidate
					break
				}
			}
		}
		allUsedIDs[strings.ToLower(newID)] = true

		newName := strings.TrimSpace(src.ProfileName)
		if newName == "" {
			newName = "导入实例"
		}
		if activeNames[strings.ToLower(newName)] {
			base := newName
			for i := 1; ; i++ {
				cand := fmt.Sprintf("%s (导入)", base)
				if i > 1 {
					cand = fmt.Sprintf("%s (导入 %d)", base, i)
				}
				if !activeNames[strings.ToLower(cand)] {
					newName = cand
					break
				}
			}
		}
		activeNames[strings.ToLower(newName)] = true

		shell := AppProfile{
			ProfileID:       newID,
			ProfileName:     newName,
			UserDataDir:     newID,
			ResolvedDataDir: resolveProfileDataDir(inst, newID, newID),
		}
		item.Action = "create"
		item.NewShellProfile = &shell
		item.WillSyncFingerprint = srcCanSyncFP
		item.WillSyncProxy = srcCanSyncProxy
		if srcCanSyncProxy {
			item.Detail = "自动创建最小实例并同步原代理"
		} else {
			item.Detail = "自动创建最小空壳实例（代理留空以防直连泄 IP）"
		}
		if !srcCanSyncFP && src.FingerprintHash != "" {
			item.FingerprintDiff = true
		}
		items = append(items, item)
		toCreate = append(toCreate, shell)
	}

	return items, toCreate, nil
}

func runImport(opts ImportOptions) (*ImportSummary, error) {
	matchBy, err := normalizeMatchBy(opts.MatchBy)
	if err != nil {
		return nil, err
	}
	opts.MatchBy = matchBy

	cookieMode, err := normalizeCookieMode(opts.CookieMode)
	if err != nil {
		return nil, err
	}
	opts.CookieMode = cookieMode

	inst, err := resolveAppInstallation(opts.AppRoot)
	if err != nil {
		return nil, err
	}

	manifest, innerZip, err := openSessionArchivePayload(opts.InputPath, opts.Password)
	if err != nil {
		return nil, err
	}

	if opts.SyncFingerprint && !manifestHasFingerprintData(manifest) {
		return nil, fmt.Errorf("该迁移包导出时未包含核心指纹（请导出时加 --include-fingerprint，或导入时去掉 --sync-fingerprint）")
	}
	if opts.SyncProxy && !manifestHasProxyData(manifest) {
		return nil, fmt.Errorf("该迁移包导出时未包含代理 IP 绑定（请导出时加 --include-proxy，或导入时去掉 --sync-proxy）")
	}

	planItems, toCreate, err := planImport(inst, manifest, opts)
	if err != nil {
		return nil, err
	}

	summary := &ImportSummary{
		TargetRoot: inst.AppRoot,
		TargetMode: inst.Mode,
		DryRun:     opts.DryRun,
		Items:      planItems,
		Warnings:   append([]string{}, manifest.Warnings...),
	}

	willWriteExtrasDB := false
	for _, item := range planItems {
		switch item.Action {
		case "match-id", "match-name":
			summary.MatchedCount++
		case "create":
			summary.CreatedCount++
		default:
			summary.SkippedCount++
		}
		if item.WillSyncFingerprint || item.WillSyncProxy {
			willWriteExtrasDB = true
		}
		if item.FingerprintDiff {
			summary.FingerprintDiffCount++
		}
		if item.Source.HasRotatingGoogleTokens {
			summary.RotatingGoogleProfiles++
		}
	}

	if opts.DryRun {
		return summary, nil
	}

	if summary.MatchedCount == 0 && summary.CreatedCount == 0 {
		return summary, nil
	}

	// 任何需要写入目标 app.db 的操作（建空壳 / 同步指纹 / 同步代理），均需先确保 Ant Browser 主程序已退出
	needsAppDBWrite := len(toCreate) > 0 || willWriteExtrasDB
	if needsAppDBWrite && !opts.Force {
		if procs := listRunningAntBrowserProcesses(); len(procs) > 0 {
			return nil, fmt.Errorf("检测到 Ant Browser 主程序正在运行（%s）。当前操作需要写入目标 app.db（创建实例/同步指纹/同步代理），请先完全退出 Ant Browser 后再导入（或传 --force 强制继续）",
				strings.Join(procs, ", "))
		}
	}

	// 检查所有目标实例目录是否被运行中的浏览器占用
	var lockedMsgs []string
	for _, item := range planItems {
		targetDir := planItemTargetDir(item)
		if targetDir == "" || !dirExists(targetDir) {
			continue
		}
		if locked, rel := checkProfileDirInUse(targetDir); locked {
			lockedMsgs = append(lockedMsgs, fmt.Sprintf("实例「%s」目录被占用: %s", planItemTargetName(item), rel))
		}
	}
	if len(lockedMsgs) > 0 {
		return nil, fmt.Errorf("检测到目标实例正在运行，请先在目标电脑停止对应浏览器实例后再导入：\n  - %s",
			strings.Join(lockedMsgs, "\n  - "))
	}

	// 对内层载荷按 profileId 建立索引
	cookieEntries := make(map[string]*zip.File)
	fingerprintEntries := make(map[string]*zip.File)
	proxyEntries := make(map[string]*zip.File)
	storageEntries := make(map[string]map[string][]*zip.File) // profileId -> catKey -> []*zip.File
	for _, f := range innerZip.File {
		name := filepath.ToSlash(strings.TrimSpace(f.Name))
		if !strings.HasPrefix(name, "profiles/") {
			continue
		}
		rest := strings.TrimPrefix(name, "profiles/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 2 {
			continue
		}
		pid := parts[0]
		if len(parts) == 2 {
			switch parts[1] {
			case "cookies.json":
				cookieEntries[pid] = f
			case "fingerprint.json":
				fingerprintEntries[pid] = f
			case "proxy.json":
				proxyEntries[pid] = f
			}
			continue
		}
		if parts[1] == "storage" && len(parts) == 3 {
			subParts := strings.SplitN(parts[2], "/", 2)
			if len(subParts) == 2 && subParts[1] != "" {
				catKey := subParts[0]
				if storageEntries[pid] == nil {
					storageEntries[pid] = make(map[string][]*zip.File)
				}
				storageEntries[pid][catKey] = append(storageEntries[pid][catKey], f)
			}
		}
	}

	backupRoot := ""
	if !opts.NoBackup {
		backupRoot = filepath.Join(inst.UserDataRoot, ".session-migrator-backups", time.Now().Format("20060102-150405"))
	}
	backupCreated := false

	// 写入 app.db 前先自动备份目标 app.db
	if needsAppDBWrite && backupRoot != "" {
		if err := backupAppDB(inst.DBPath, backupRoot); err != nil {
			return nil, err
		}
		backupCreated = true
	}

	// 若启用了 --create-missing，先在目标 app.db 事务内创建最小空壳实例
	if len(toCreate) > 0 {
		if err := createMinimalShellProfilesInDB(inst, toCreate); err != nil {
			return nil, err
		}
	}

	// 准备可选的指纹与代理 DB 更新列表（统一在一个事务内提交）
	var dbExtras []profileDBExtraUpdate
	if willWriteExtrasDB {
		for _, item := range planItems {
			targetID := planItemTargetID(item)
			if targetID == "" || (!item.WillSyncFingerprint && !item.WillSyncProxy) {
				continue
			}
			upd := profileDBExtraUpdate{
				TargetProfileID: targetID,
			}
			if item.WillSyncFingerprint {
				if ff, ok := fingerprintEntries[item.Source.ProfileID]; ok {
					var fpDump PortableFingerprintDump
					if err := decodeZipEntryJSON(ff, &fpDump); err != nil {
						return nil, fmt.Errorf("解析实例「%s」指纹数据失败: %w", item.Source.ProfileName, err)
					}
					if len(fpDump.FingerprintArgs) > 0 {
						upd.SyncFingerprint = true
						upd.FingerprintArgs = fpDump.FingerprintArgs
					}
				} else if len(item.Source.LegacyFingerprintArgs) > 0 {
					upd.SyncFingerprint = true
					upd.FingerprintArgs = materializeEffectiveFingerprintArgs(item.Source.ProfileID, item.Source.LegacyFingerprintArgs)
				}
			}
			if item.WillSyncProxy {
				if pf, ok := proxyEntries[item.Source.ProfileID]; ok {
					var pxDump PortableProxyDump
					if err := decodeZipEntryJSON(pf, &pxDump); err != nil {
						return nil, fmt.Errorf("解析实例「%s」代理数据失败: %w", item.Source.ProfileName, err)
					}
					upd.SyncProxy = true
					upd.ProxyDump = &pxDump
				}
			}
			if upd.SyncFingerprint || upd.SyncProxy {
				dbExtras = append(dbExtras, upd)
			}
		}

		extraStats, err := applyProfileExtrasInDB(inst, dbExtras)
		if err != nil {
			return nil, err
		}
		summary.FingerprintsSynced = extraStats.FingerprintsUpdated
		summary.ProxiesBound = extraStats.ProxiesBound
		summary.ProxyNodesReused = extraStats.ProxyNodesReused
		summary.ProxyNodesInserted = extraStats.ProxyNodesInserted
		summary.VirtualGroupsSynced = extraStats.VirtualGroupsSynced
	}

	step := 0
	totalWork := summary.MatchedCount + summary.CreatedCount
	for _, item := range planItems {
		targetDir := planItemTargetDir(item)
		targetID := planItemTargetID(item)
		targetName := planItemTargetName(item)
		if targetDir == "" {
			continue
		}
		step++
		fmt.Printf("[%d/%d] 离线写入登录态 -> 「%s」(%s)...\n", step, totalWork, targetName, shortID(targetID))

		profileBackupDir := ""
		if backupRoot != "" && dirExists(targetDir) {
			profileBackupDir = filepath.Join(backupRoot, targetID)
			backupCreated = true
		}

		// 1. 恢复并按目标机 DPAPI 重新加密 Cookies
		if cf, ok := cookieEntries[item.Source.ProfileID]; ok {
			var dump ProfileCookieDump
			if decErr := decodeZipEntryJSON(cf, &dump); decErr != nil {
				return nil, fmt.Errorf("解析归档 Cookie 失败（%s）: %w", item.Source.ProfileName, decErr)
			}

			written, _, impErr := importProfileCookies(targetDir, dump, opts.CookieMode, profileBackupDir)
			if impErr != nil {
				return nil, fmt.Errorf("写入目标实例「%s」Cookie 失败: %w", targetName, impErr)
			}
			summary.TotalCookiesWritten += written
		}

		// 2. 恢复 Web Storage（仅替换归档内实际存在的类别）
		if catMap := storageEntries[item.Source.ProfileID]; len(catMap) > 0 {
			for _, cat := range allStorageCategories() {
				files := catMap[cat.Key]
				if len(files) == 0 {
					continue
				}
				restored, sErr := restoreProfileStorageCategory(files, targetDir, cat, profileBackupDir)
				if sErr != nil {
					return nil, fmt.Errorf("恢复目标实例「%s」%s 失败: %w", targetName, cat.RelDir, sErr)
				}
				summary.TotalStorageFiles += restored
			}
		}
	}

	if backupCreated {
		summary.BackupRoot = backupRoot
	}
	return summary, nil
}

func decodeZipEntryJSON(f *zip.File, dst any) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	return json.NewDecoder(rc).Decode(dst)
}

func filterArchiveProfiles(profiles []ArchiveProfileMetadata, filters []string) (matched []ArchiveProfileMetadata, missing []string) {
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

func planItemTargetDir(item ImportPlanItem) string {
	if item.TargetProfile != nil {
		return item.TargetProfile.ResolvedDataDir
	}
	if item.NewShellProfile != nil {
		return item.NewShellProfile.ResolvedDataDir
	}
	return ""
}

func planItemTargetID(item ImportPlanItem) string {
	if item.TargetProfile != nil {
		return item.TargetProfile.ProfileID
	}
	if item.NewShellProfile != nil {
		return item.NewShellProfile.ProfileID
	}
	return ""
}

func planItemTargetName(item ImportPlanItem) string {
	if item.TargetProfile != nil {
		return item.TargetProfile.ProfileName
	}
	if item.NewShellProfile != nil {
		return item.NewShellProfile.ProfileName
	}
	return item.Source.ProfileName
}
