package backend

import (
	"ant-chrome/backend/internal/logger"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// backupCleanEncryptedFiles 清理目标 profile 用户数据目录中被 DPAPI 加密的文件。
// 删除的文件（跨设备不可用）：
//   - Default/Cookies, Default/Cookies-journal
//
// 保留的文件（不加密，文件复制即可）：
//   - Default/Local Storage/, Default/IndexedDB/, Default/Session Storage/
//   - Default/Preferences, Default/Bookmarks
func backupCleanEncryptedFiles(userDataDir string) error {
	log := logger.New("Backup")

	// 需要删除的 DPAPI 加密文件
	encryptedFiles := []string{
		filepath.Join(userDataDir, "Default", "Cookies"),
		filepath.Join(userDataDir, "Default", "Cookies-journal"),
	}

	for _, f := range encryptedFiles {
		if _, err := os.Stat(f); err == nil {
			if err := os.Remove(f); err != nil {
				log.Warn("清理加密文件失败",
					logger.F("file", f),
					logger.F("error", err.Error()),
				)
			} else {
				log.Info("已清理加密文件", logger.F("file", filepath.Base(f)))
			}
		}
	}

	// 修复 Local State 文件
	if err := backupFixLocalState(userDataDir); err != nil {
		log.Warn("修复 Local State 失败",
			logger.F("dir", userDataDir),
			logger.F("error", err.Error()),
		)
	}

	return nil
}

// backupFixLocalState 修复 Local State 文件。
// 移除 os_crypt 字段中的 encrypted_key，让 Chromium 在新设备上自动生成新密钥。
func backupFixLocalState(userDataDir string) error {
	localStatePath := filepath.Join(userDataDir, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，无需修复
		}
		return fmt.Errorf("读取 Local State 失败: %w", err)
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return fmt.Errorf("解析 Local State 失败: %w", err)
	}

	// 移除 os_crypt 段，Chromium 启动时会自动生成新的
	modified := false
	if _, exists := localState["os_crypt"]; exists {
		delete(localState, "os_crypt")
		modified = true
	}

	if !modified {
		return nil
	}

	newData, err := json.Marshal(localState)
	if err != nil {
		return fmt.Errorf("序列化 Local State 失败: %w", err)
	}

	if err := os.WriteFile(localStatePath, newData, 0644); err != nil {
		return fmt.Errorf("写入 Local State 失败: %w", err)
	}

	logger.New("Backup").Info("Local State 已修复：移除旧 os_crypt 密钥",
		logger.F("path", localStatePath),
	)
	return nil
}

// backupImportProfileCookies 为单个 profile 注入 Cookie。
// 启动实例 → 等待就绪 → 清除旧 Cookie → 注入新 Cookie → 关闭。
func (a *App) backupImportProfileCookies(profileId string, cookies []CookieInfo) error {
	log := logger.New("Backup")

	if len(cookies) == 0 {
		return nil
	}

	log.Info("Cookie 导入：启动实例",
		logger.F("profile_id", profileId),
		logger.F("cookie_count", len(cookies)),
	)

	// 使用直连代理、about:blank 启动
	_, err := a.browserInstanceStartInternal(
		profileId,
		nil,                     // extraLaunchArgs
		[]string{"about:blank"}, // startURLs
		true,                    // skipDefaultStartURLs
		false,                   // preferVisibleWindow
		true,                    // forceDirectProxy
		"",                      // proxyId
		"",                      // proxyConfig
	)
	if err != nil {
		return fmt.Errorf("Cookie 注入启动实例失败 (%s): %w", profileId, err)
	}

	// 等待调试端口就绪
	a.browserMgr.Mutex.Lock()
	profile := a.browserMgr.Profiles[profileId]
	debugPort := 0
	if profile != nil {
		debugPort = profile.DebugPort
	}
	a.browserMgr.Mutex.Unlock()

	if debugPort > 0 {
		_, _ = a.waitForBrowserDebugReady(profileId, debugPort, 8*time.Second)
	}

	// 重新获取端口确认就绪
	a.browserMgr.Mutex.Lock()
	profile = a.browserMgr.Profiles[profileId]
	if profile != nil && profile.DebugReady {
		debugPort = profile.DebugPort
	} else {
		debugPort = 0
	}
	a.browserMgr.Mutex.Unlock()

	if debugPort == 0 {
		_ = a.backupAutoStopProfile(profileId)
		return fmt.Errorf("实例调试端口不可用: %s", profileId)
	}

	// 清除现有 Cookie（可能有浏览器自动创建的新 Cookie）
	if err := cdpClearAllCookies(debugPort); err != nil {
		log.Warn("清除现有 Cookie 失败，继续注入",
			logger.F("profile_id", profileId),
			logger.F("error", err.Error()),
		)
	}

	// 注入保存的 Cookie
	if err := cdpSetCookies(debugPort, cookies); err != nil {
		_ = a.backupAutoStopProfile(profileId)
		return fmt.Errorf("CDP Cookie 注入失败 (%s): %w", profileId, err)
	}

	log.Info("Cookie 注入成功",
		logger.F("profile_id", profileId),
		logger.F("cookie_count", len(cookies)),
	)

	// 关闭实例
	if err := a.backupAutoStopProfile(profileId); err != nil {
		log.Warn("Cookie 注入后关闭实例失败",
			logger.F("profile_id", profileId),
			logger.F("error", err.Error()),
		)
	}

	return nil
}

// backupImportAllProfileCookies 遍历所有有 Cookie 数据的 profile，逐个注入。
func (a *App) backupImportAllProfileCookies(
	cookieMap map[string][]CookieInfo,
	emitProgress func(phase string, progress int, message string, meta *backupProgressMeta),
) error {
	log := logger.New("Backup")

	emit := func(phase string, progress int, message string) {
		if emitProgress != nil {
			emitProgress(phase, progress, message, nil)
		}
	}

	if len(cookieMap) == 0 {
		return nil
	}

	// 收集 profile 名称用于日志
	a.browserMgr.Mutex.Lock()
	profileNames := make(map[string]string)
	for id, p := range a.browserMgr.Profiles {
		profileNames[id] = p.ProfileName
	}
	a.browserMgr.Mutex.Unlock()

	total := len(cookieMap)
	successCount := 0
	failCount := 0
	idx := 0

	for profileId, cookies := range cookieMap {
		name := profileNames[profileId]
		if name == "" {
			name = profileId
		}
		progress := int(float64(idx) / float64(total) * 100)
		emit("cookies-import", progress, fmt.Sprintf("正在恢复登录状态 (%d/%d): %s", idx+1, total, name))

		if err := a.backupImportProfileCookies(profileId, cookies); err != nil {
			failCount++
			log.Warn("Cookie 注入失败，跳过该实例",
				logger.F("profile_id", profileId),
				logger.F("profile_name", name),
				logger.F("error", err.Error()),
			)
		} else {
			successCount++
		}

		idx++
	}

	emit("cookies-import", 100, fmt.Sprintf("登录状态恢复完成：成功 %d / 失败 %d / 总计 %d", successCount, failCount, total))
	log.Info("Cookie 批量导入完成",
		logger.F("success", successCount),
		logger.F("failed", failCount),
		logger.F("total", total),
	)

	return nil
}

// backupLoadCookieEntries 从解压目录中读取 Cookie JSON 文件。
// 查找路径：payload/browser/cookies/<profileId>.json
func backupLoadCookieEntries(payloadRoot string) map[string][]CookieInfo {
	cookieDir := filepath.Join(payloadRoot, "browser", "cookies")
	entries, err := os.ReadDir(cookieDir)
	if err != nil {
		return nil
	}

	result := make(map[string][]CookieInfo)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		profileId := strings.TrimSuffix(name, ".json")
		if profileId == "" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(cookieDir, name))
		if err != nil {
			continue
		}

		cookies, err := backupDeserializeCookiesFromJSON(data)
		if err != nil {
			continue
		}
		if len(cookies) > 0 {
			result[profileId] = cookies
		}
	}

	return result
}
