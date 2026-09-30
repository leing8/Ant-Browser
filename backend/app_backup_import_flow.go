package backend

import (
	"ant-chrome/backend/internal/logger"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) backupImportFromPathLocked(zipPath string) (map[string]interface{}, error) {
	a.backupEmitImportProgress("preparing", 10, "正在解压并校验备份包...")
	extractRoot, manifest, err := backupExtractAndValidate(zipPath)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(extractRoot)
	if err := a.backupStopRuntimeForMaintenance(); err != nil {
		return nil, fmt.Errorf("停止运行时失败，已中止备份导入: %w", err)
	}
	a.backupEmitImportProgress("preparing", 20, "备份包校验通过，开始导入数据...")

	componentEntries := backupDetectPresentManifestEntries(extractRoot, manifest)
	issueTracker := newBackupImportTracker(componentEntries)

	stats := &backupMergeStats{}

	payloadRoot := filepath.Join(extractRoot, "payload")
	a.backupEmitImportProgress("importing", 45, "正在解析备份配置...")
	incomingCfg, hasIncomingCfg, err := backupLoadIncomingConfig(payloadRoot)
	if err != nil {
		issueTracker.RecordIssue("system_config_main", "主配置文件", fmt.Errorf("解析配置失败: %w", err))
		incomingCfg = nil
		hasIncomingCfg = false
	}
	if hasIncomingCfg {
		incomingCfg = a.backupNormalizeImportedConfigPaths(incomingCfg, a.config)
	}

	var importMappings *backupImportReferenceMappings
	if dbSrc := backupFindDatabaseFile(payloadRoot); dbSrc != "" {
		a.backupEmitImportProgress("importing", 76, "正在合并数据库数据...")
		importMappings, err = a.backupMergeDatabaseFromSource(dbSrc, incomingCfg, stats)
		if err != nil {
			issueTracker.RecordIssue("database_sqlite_main", "SQLite 主数据库", err)
		}
	} else if _, ok := componentEntries["database_sqlite_main"]; ok {
		issueTracker.RecordIssue("database_sqlite_main", "SQLite 主数据库", fmt.Errorf("备份包缺少数据库文件"))
	}

	if hasIncomingCfg {
		a.backupEmitImportProgress("importing", 82, "正在应用系统配置...")
		if err := a.backupApplyIncomingConfig(incomingCfg); err != nil {
			issueTracker.RecordIssue("system_config_main", "主配置文件", err)
		}
	}

	a.backupEmitImportProgress("importing", 84, "正在合并代理配置...")
	if err := a.backupMergeProxiesFile(payloadRoot, stats); err != nil {
		issueTracker.RecordIssue("system_config_proxies", "代理配置文件", err)
	}

	a.backupEmitImportProgress("importing", 86, "正在同步文件数据...")
	a.backupImportFileTrees(payloadRoot, incomingCfg, manifest, stats, issueTracker.RecordIssue, importMappings)

	a.backupEmitImportProgress("importing", 92, "正在修复插件迁移路径...")
	repairIssues, err := a.backupRepairExtensionPathsAfterImport()
	if err != nil {
		issueTracker.RecordIssue("browser_extension_paths", "插件路径迁移", err)
	}
	for _, issue := range repairIssues {
		issueTracker.RecordIssue("browser_extension_paths", "插件路径迁移", issue)
	}

	a.backupEmitImportProgress("importing", 94, "正在刷新运行时配置...")
	if err := a.backupReloadAfterMutation(); err != nil {
		return nil, err
	}

	// ========================================================================
	// Cookie 迁移：清理加密文件 + CDP 注入（保持登录状态）
	// ========================================================================
	cookieMap := backupLoadCookieEntries(payloadRoot)
	if importMappings != nil && len(importMappings.Profiles) > 0 {
		remappedCookieMap := make(map[string][]CookieInfo, len(cookieMap))
		for profileId, cookies := range cookieMap {
			targetProfileId := profileId
			if mapping, ok := importMappings.Profiles[profileId]; ok && strings.TrimSpace(mapping.TargetID) != "" {
				targetProfileId = mapping.TargetID
			}
			remappedCookieMap[targetProfileId] = cookies
		}
		cookieMap = remappedCookieMap
	}
	cookieProfileCount := 0
	cookieInjectSuccess := 0

	if len(cookieMap) > 0 {
		log := logger.New("Backup")
		log.Info("检测到 Cookie 备份数据，开始恢复登录状态",
			logger.F("profiles", len(cookieMap)),
		)

		// 1. 清理所有相关 profile 的 DPAPI 加密文件
		a.backupEmitImportProgress("cookies-cleanup", 95, "正在清理旧加密数据...")
		for profileId := range cookieMap {
			a.browserMgr.Mutex.Lock()
			profile, exists := a.browserMgr.Profiles[profileId]
			a.browserMgr.Mutex.Unlock()

			if !exists {
				log.Warn("Cookie 恢复：profile 不存在，跳过",
					logger.F("profile_id", profileId),
				)
				continue
			}

			userDataDir := a.browserMgr.ResolveUserDataDir(profile)
			backupCleanEncryptedFiles(userDataDir)
			cookieProfileCount++
		}

		// 2. 逐个 profile 启动 → 注入 Cookie → 关闭
		a.backupEmitImportProgress("cookies-import", 97, "正在恢复登录状态...")
		_ = a.backupImportAllProfileCookies(cookieMap, a.backupEmitImportProgressMeta)

		// 统计成功数
		for profileId := range cookieMap {
			a.browserMgr.Mutex.Lock()
			_, exists := a.browserMgr.Profiles[profileId]
			a.browserMgr.Mutex.Unlock()
			if exists {
				cookieInjectSuccess++
			}
		}
	}

	totalComponents, successCount, failedCount, partial := issueTracker.Summary()
	message := "导入完成"
	if len(cookieMap) > 0 {
		message = fmt.Sprintf("导入完成（含 %d 个实例登录状态恢复）", cookieProfileCount)
	}
	if partial {
		message = fmt.Sprintf("导入完成（部分成功）：成功 %d 个模块，异常 %d 个模块", successCount, failedCount)
	}
	a.backupEmitImportProgress("done", 100, message)

	return map[string]interface{}{
		"cancelled":           false,
		"zipPath":             zipPath,
		"imported":            stats.Imported,
		"skipped":             stats.Skipped,
		"conflicts":           stats.Conflicts,
		"partial":             partial,
		"componentTotal":      totalComponents,
		"componentSuccess":    successCount,
		"componentFailed":     failedCount,
		"failedComponents":    issueTracker.FailedComponents(),
		"cookieProfiles":      cookieProfileCount,
		"cookieInjectSuccess": cookieInjectSuccess,
		"message":             message,
	}, nil
}
