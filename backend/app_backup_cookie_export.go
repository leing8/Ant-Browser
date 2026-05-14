package backend

import (
	"ant-chrome/backend/internal/logger"
	"encoding/json"
	"fmt"
	"time"
)

// backupExportProfileCookies 通过 CDP 从单个 profile 提取 Cookie。
// 如果实例未运行，自动启动 → 提取 → 关闭。
// 返回 cookies, wasAutoStarted, error。
func (a *App) backupExportProfileCookies(profileId string) ([]CookieInfo, bool, error) {
	log := logger.New("Backup")
	autoStarted := false

	a.browserMgr.Mutex.Lock()
	profile, exists := a.browserMgr.Profiles[profileId]
	if !exists {
		a.browserMgr.Mutex.Unlock()
		return nil, false, fmt.Errorf("profile 不存在: %s", profileId)
	}
	isRunning := profile.Running && profile.DebugReady && profile.DebugPort > 0
	a.browserMgr.Mutex.Unlock()

	// 如果实例未运行，自动启动
	if !isRunning {
		log.Info("Cookie 导出：自动启动实例",
			logger.F("profile_id", profileId),
			logger.F("profile_name", profile.ProfileName),
		)
		if err := a.backupAutoStartForCookieExport(profileId); err != nil {
			return nil, false, fmt.Errorf("自动启动实例失败 (%s): %w", profileId, err)
		}
		autoStarted = true
	}

	// 获取调试端口
	a.browserMgr.Mutex.Lock()
	profile = a.browserMgr.Profiles[profileId]
	debugPort := 0
	if profile != nil && profile.Running && profile.DebugReady {
		debugPort = profile.DebugPort
	}
	a.browserMgr.Mutex.Unlock()

	if debugPort == 0 {
		if autoStarted {
			_ = a.backupAutoStopProfile(profileId)
		}
		return nil, autoStarted, fmt.Errorf("实例调试端口不可用: %s", profileId)
	}

	// 通过 CDP 提取 Cookie
	cookies, err := cdpGetAllCookies(debugPort)
	if err != nil {
		if autoStarted {
			_ = a.backupAutoStopProfile(profileId)
		}
		return nil, autoStarted, fmt.Errorf("CDP Cookie 提取失败 (%s): %w", profileId, err)
	}

	log.Info("Cookie 导出成功",
		logger.F("profile_id", profileId),
		logger.F("cookie_count", len(cookies)),
		logger.F("auto_started", autoStarted),
	)

	// 如果是自动启动的，提取完毕后关闭
	if autoStarted {
		if err := a.backupAutoStopProfile(profileId); err != nil {
			log.Warn("Cookie 导出后自动关闭实例失败",
				logger.F("profile_id", profileId),
				logger.F("error", err.Error()),
			)
		}
	}

	return cookies, autoStarted, nil
}

// backupExportAllProfileCookies 遍历所有 profile，逐个提取 Cookie。
// 返回 map[profileId][]CookieInfo。
func (a *App) backupExportAllProfileCookies(
	emitProgress func(phase string, progress int, message string, meta *backupProgressMeta),
) (map[string][]CookieInfo, error) {
	log := logger.New("Backup")

	emit := func(phase string, progress int, message string) {
		if emitProgress != nil {
			emitProgress(phase, progress, message, nil)
		}
	}

	// 收集所有 profile ID
	a.browserMgr.Mutex.Lock()
	profileIDs := make([]string, 0, len(a.browserMgr.Profiles))
	profileNames := make(map[string]string)
	for id, p := range a.browserMgr.Profiles {
		profileIDs = append(profileIDs, id)
		profileNames[id] = p.ProfileName
	}
	a.browserMgr.Mutex.Unlock()

	if len(profileIDs) == 0 {
		return nil, nil
	}

	result := make(map[string][]CookieInfo)
	total := len(profileIDs)
	successCount := 0
	failCount := 0

	for i, profileId := range profileIDs {
		name := profileNames[profileId]
		if name == "" {
			name = profileId
		}
		progress := int(float64(i) / float64(total) * 100)
		emit("cookies-export", progress, fmt.Sprintf("正在提取实例 Cookie (%d/%d): %s", i+1, total, name))

		cookies, _, err := a.backupExportProfileCookies(profileId)
		if err != nil {
			failCount++
			log.Warn("Cookie 导出失败，跳过该实例",
				logger.F("profile_id", profileId),
				logger.F("profile_name", name),
				logger.F("error", err.Error()),
			)
			continue
		}

		if len(cookies) > 0 {
			result[profileId] = cookies
			successCount++
		}
	}

	emit("cookies-export", 100, fmt.Sprintf("Cookie 提取完成：成功 %d / 失败 %d / 总计 %d", successCount, failCount, total))
	log.Info("Cookie 批量导出完成",
		logger.F("success", successCount),
		logger.F("failed", failCount),
		logger.F("total", total),
	)

	return result, nil
}

// backupAutoStartForCookieExport 为 Cookie 导出自动启动一个未运行的实例。
// 使用 about:blank 最小化加载，使用直连代理，跳过默认首页。
func (a *App) backupAutoStartForCookieExport(profileId string) error {
	// 使用直连代理、about:blank 启动，跳过默认首页
	_, err := a.browserInstanceStartInternal(
		profileId,
		nil,                     // extraLaunchArgs
		[]string{"about:blank"}, // startURLs
		true,                    // skipDefaultStartURLs
		false,                   // preferVisibleWindow
		true,                    // forceDirectProxy — 避免代理连接超时
		"",                      // proxyId
		"",                      // proxyConfig
	)
	if err != nil {
		return err
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
	return nil
}

// backupAutoStopProfile 停止一个自动启动的实例。
func (a *App) backupAutoStopProfile(profileId string) error {
	_, err := a.BrowserInstanceStop(profileId)
	return err
}

// backupSerializeCookiesToJSON 将 Cookie 序列化为 JSON 字节。
func backupSerializeCookiesToJSON(cookies []CookieInfo) ([]byte, error) {
	return json.MarshalIndent(cookies, "", "  ")
}

// backupDeserializeCookiesFromJSON 从 JSON 字节反序列化 Cookie。
func backupDeserializeCookiesFromJSON(data []byte) ([]CookieInfo, error) {
	var cookies []CookieInfo
	if err := json.Unmarshal(data, &cookies); err != nil {
		return nil, fmt.Errorf("Cookie JSON 解析失败: %w", err)
	}
	return cookies, nil
}
