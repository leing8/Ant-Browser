package browser

import (
	"ant-chrome/backend/internal/logger"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// copyFingerprintArgsWithNewSeed 复制源实例的指纹配置参数，但替换指纹种子为新的随机值。
// 指纹浏览器最佳实践：复制实例时保留所有用户配置（分辨率、WebGL、语言等），
// 仅重新生成种子（--fingerprint=<seed>），使每个副本拥有独立的 Canvas / Audio / WebGL 噪声特征。
func copyFingerprintArgsWithNewSeed(srcArgs []string) []string {
	args := make([]string, 0, len(srcArgs))
	seedReplaced := false

	for _, arg := range srcArgs {
		if strings.HasPrefix(arg, "--fingerprint=") {
			// 替换种子为新的随机值
			args = append(args, "--fingerprint="+randomSeed())
			seedReplaced = true
		} else {
			args = append(args, arg)
		}
	}

	// 如果源实例没有显式种子，也生成一个新的（确保副本有独立指纹）
	if !seedReplaced {
		args = append([]string{"--fingerprint=" + randomSeed()}, args...)
	}

	return args
}

// randomSeed 生成随机指纹种子（32位正整数字符串）
func randomSeed() string {
	return strconv.Itoa(rand.Intn(2147483646) + 1)
}

const (
	copyModeRegular         = "regular"
	copyModeAutoFingerprint = "auto_fingerprint"

	copyAutomationTargetSeed     = "seed"
	copyAutomationTargetIdentity = "identity"
	copyAutomationTargetLocale   = "locale"
	copyAutomationTargetScreen   = "screen"
	copyAutomationTargetHardware = "hardware"
	copyAutomationTargetNetwork  = "network"
)

var legacyCopyAutomationTargetAliases = map[string]string{
	"render":  copyAutomationTargetSeed,
	"fonts":   copyAutomationTargetSeed,
	"devices": copyAutomationTargetSeed,
}

var profileCopyNameSuffixPattern = regexp.MustCompile(`[[:space:]]*(?:\([[:space:]]*副本[[:space:]]*\)|（副本）)[[:space:]]*(?:[0-9]{12})?$`)
func (m *Manager) Copy(profileId string, newName string) (*Profile, error) {
	return m.copyProfile(profileId, newName, func(*Profile) []string {
		return append([]string{}, m.Config.Browser.DefaultFingerprintArgs...)
	})
}

// CopyWithMode 按模式复制实例配置。
// regular: 保留原实例指纹参数。
// auto_fingerprint: 保留原指纹模板，但移除显式种子，让新实例自动生成新种子。
func (m *Manager) CopyWithMode(profileId string, newName string, mode string) (*Profile, error) {
	return m.CopyWithOptions(profileId, newName, ProfileCopyOptions{Mode: mode})
}

// CopyWithOptions 按结构化选项复制实例配置。
func (m *Manager) CopyWithOptions(profileId string, newName string, options ProfileCopyOptions) (*Profile, error) {
	normalizedMode := normalizeCopyMode(options.Mode)
	normalizedTargets, err := normalizeCopyAutomationTargets(options.AutomationTargets)
	if err != nil {
		return nil, err
	}
	return m.copyProfile(profileId, newName, func(src *Profile) []string {
		switch normalizedMode {
		case copyModeRegular:
			return append([]string{}, src.FingerprintArgs...)
		default:
			return buildAutoFingerprintArgs(src.FingerprintArgs, m.Config.Browser.DefaultFingerprintArgs, normalizedTargets)
		}
	})
}

func (m *Manager) copyProfile(profileId string, newName string, fingerprintResolver func(*Profile) []string) (*Profile, error) {
	log := logger.New("Browser")
	m.InitData()
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	src, exists := m.Profiles[profileId]
	if !exists {
		log.Error("源实例不存在", logger.F("profile_id", profileId))
		return nil, fmt.Errorf("profile not found")
	}

	now := time.Now()
	nowText := now.Format(time.RFC3339)
	newId := uuid.NewString()

	profileName := strings.TrimSpace(newName)
	if profileName == "" {
		profileName = buildProfileCopyName(src.ProfileName, now)
	}

	profile := &Profile{
		ProfileId:          newId,
		ProfileName:        profileName,
		UserDataDir:        newId,
		CoreId:             normalizeProfileCoreID(src.CoreId),
		RestoreLastSession: NormalizeRestoreLastSessionMode(src.RestoreLastSession),
		FingerprintArgs:    fingerprintResolver(src),
		ProxyId:            src.ProxyId,
		ProxyConfig:        src.ProxyConfig,
		ProxyBindSourceID:  src.ProxyBindSourceID,
		ProxyBindSourceURL: src.ProxyBindSourceURL,
		ProxyBindName:      src.ProxyBindName,
		ProxyBindUpdatedAt: src.ProxyBindUpdatedAt,
		MemoryLimitMB:      normalizeMemoryLimitMB(src.MemoryLimitMB),
		LaunchArgs:         append([]string{}, src.LaunchArgs...),
		Tags:               append([]string{}, src.Tags...),
		Keywords:           append([]string{}, src.Keywords...),
		GroupId:            src.GroupId,
		Running:            false,
		DebugPort:          0,
		Pid:                0,
		LastError:          "",
		CreatedAt:          nowText,
		UpdatedAt:          nowText,
	}

	m.Profiles[newId] = profile
	log.Info("实例复制成功", logger.F("src_id", profileId), logger.F("new_id", newId), logger.F("new_name", profileName))

	if err := m.SaveProfiles(); err != nil {
		return nil, err
	}

	m.ensureProfileLaunchCode(profile)
	return profile, nil
}

// CopyMultiple 批量复制实例（复制 count 个副本，保留指纹配置，每个副本生成新的指纹种子）
func (m *Manager) CopyMultiple(profileId string, newName string, count int) ([]*Profile, error) {
	log := logger.New("Browser")
	m.InitData()
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if count < 1 {
		count = 1
	}
	if count > 100 {
		return nil, fmt.Errorf("单次复制数量不能超过 100")
	}

	src, exists := m.Profiles[profileId]
	if !exists {
		log.Error("源实例不存在", logger.F("profile_id", profileId))
		return nil, fmt.Errorf("profile not found")
	}

	baseName := strings.TrimSpace(newName)
	if baseName == "" {
		baseName = src.ProfileName + " (副本)"
	}

	results := make([]*Profile, 0, count)
	for i := 0; i < count; i++ {
		now := time.Now().Format(time.RFC3339)
		newId := uuid.NewString()

		profileName := baseName
		if count > 1 {
			profileName = fmt.Sprintf("%s_%d", baseName, i+1)
		}

		profile := &Profile{
			ProfileId:          newId,
			ProfileName:        profileName,
			UserDataDir:        newId,
			CoreId:             normalizeProfileCoreID(src.CoreId),
			RestoreLastSession: NormalizeRestoreLastSessionMode(src.RestoreLastSession),
			FingerprintArgs:    copyFingerprintArgsWithNewSeed(src.FingerprintArgs),
			ProxyId:            src.ProxyId,
			ProxyConfig:        src.ProxyConfig,
			ProxyBindSourceID:  src.ProxyBindSourceID,
			ProxyBindSourceURL: src.ProxyBindSourceURL,
			ProxyBindName:      src.ProxyBindName,
			ProxyBindUpdatedAt: src.ProxyBindUpdatedAt,
			MemoryLimitMB:      normalizeMemoryLimitMB(src.MemoryLimitMB),
			LaunchArgs:         append([]string{}, src.LaunchArgs...),
			Tags:               append([]string{}, src.Tags...),
			Keywords:           append([]string{}, src.Keywords...),
			GroupId:            src.GroupId,
			Running:            false,
			DebugPort:          0,
			Pid:                0,
			LastError:          "",
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		m.Profiles[newId] = profile
		results = append(results, profile)
		log.Info("实例复制成功", logger.F("src_id", profileId), logger.F("new_id", newId), logger.F("new_name", profileName), logger.F("index", i+1), logger.F("total", count))
	}

	if err := m.SaveProfiles(); err != nil {
		return nil, err
	}

	for _, p := range results {
		m.ensureProfileLaunchCode(p)
	}
	return results, nil
}

func buildProfileCopyName(sourceName string, now time.Time) string {
	baseName := normalizeProfileCopyBaseName(sourceName)
	if baseName == "" {
		baseName = "未命名实例"
	}
	return fmt.Sprintf("%s（副本）%s", baseName, now.Format("060102150405"))
}

func normalizeProfileCopyBaseName(sourceName string) string {
	trimmed := strings.TrimSpace(sourceName)
	if trimmed == "" {
		return ""
	}

	baseName := trimmed
	for baseName != "" {
		nextName := strings.TrimSpace(profileCopyNameSuffixPattern.ReplaceAllString(baseName, ""))
		if nextName == baseName {
			break
		}
		if nextName == "" {
			return trimmed
		}
		baseName = nextName
	}

	return baseName
}

func normalizeCopyMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case copyModeRegular:
		return copyModeRegular
	default:
		return copyModeAutoFingerprint
	}
}

func normalizeCopyAutomationTargets(targets []string) ([]string, error) {
	if len(targets) == 0 {
		return defaultCopyAutomationTargets(), nil
	}

	normalized := make([]string, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	unknown := make([]string, 0)

	for _, target := range targets {
		value := strings.ToLower(strings.TrimSpace(target))
		if value == "" {
			continue
		}
		if alias, ok := legacyCopyAutomationTargetAliases[value]; ok {
			value = alias
		}
		if _, ok := copyAutomationTargetArgPrefixes()[value]; !ok {
			unknown = append(unknown, value)
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	if len(unknown) > 0 {
		return nil, fmt.Errorf("复制实例失败：包含不支持的自动化指纹项（%s）。", strings.Join(unknown, ", "))
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("复制实例失败：请至少选择一个自动化指纹项。")
	}
	return normalized, nil
}

func defaultCopyAutomationTargets() []string {
	return []string{copyAutomationTargetSeed}
}

func buildAutoFingerprintArgs(sourceArgs []string, defaultArgs []string, targets []string) []string {
	base := sourceArgs
	if len(base) == 0 {
		base = defaultArgs
	}
	if len(targets) == 0 {
		targets = defaultCopyAutomationTargets()
	}
	return applyCopyAutomationTargets(base, defaultArgs, targets)
}

func applyCopyAutomationTargets(baseArgs []string, defaultArgs []string, targets []string) []string {
	if len(baseArgs) == 0 {
		return []string{}
	}

	targetSet := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		targetSet[target] = struct{}{}
	}

	defaultArgsByKey := mapArgsByKey(defaultArgs)
	outputArgs := make([]string, 0, len(baseArgs))
	outputKeys := make(map[string]struct{}, len(baseArgs))

	for _, arg := range baseArgs {
		trimmed := strings.TrimSpace(arg)
		if trimmed == "" {
			continue
		}

		key, ok := copyFingerprintArgKey(trimmed)
		if !ok {
			outputArgs = append(outputArgs, trimmed)
			continue
		}

		target, ok := copyFingerprintArgTarget(key)
		if !ok {
			outputArgs = append(outputArgs, trimmed)
			outputKeys[key] = struct{}{}
			continue
		}

		if _, targeted := targetSet[target]; !targeted {
			outputArgs = append(outputArgs, trimmed)
			outputKeys[key] = struct{}{}
			continue
		}

		if replacement, ok := defaultArgsByKey[key]; ok {
			if _, exists := outputKeys[key]; !exists {
				outputArgs = append(outputArgs, replacement)
				outputKeys[key] = struct{}{}
			}
		}
	}

	for _, arg := range defaultArgs {
		trimmed := strings.TrimSpace(arg)
		if trimmed == "" {
			continue
		}
		key, ok := copyFingerprintArgKey(trimmed)
		if !ok {
			continue
		}
		target, ok := copyFingerprintArgTarget(key)
		if !ok {
			continue
		}
		if _, targeted := targetSet[target]; !targeted {
			continue
		}
		if _, exists := outputKeys[key]; exists {
			continue
		}
		outputArgs = append(outputArgs, trimmed)
		outputKeys[key] = struct{}{}
	}

	return outputArgs
}

func mapArgsByKey(args []string) map[string]string {
	out := make(map[string]string, len(args))
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if trimmed == "" {
			continue
		}
		key, ok := copyFingerprintArgKey(trimmed)
		if !ok {
			continue
		}
		out[key] = trimmed
	}
	return out
}

func copyFingerprintArgKey(arg string) (string, bool) {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" || !strings.HasPrefix(trimmed, "--") {
		return "", false
	}
	eqIdx := strings.Index(trimmed, "=")
	if eqIdx <= 0 {
		return strings.ToLower(trimmed), true
	}
	return strings.ToLower(trimmed[:eqIdx]), true
}

func copyFingerprintArgTarget(key string) (string, bool) {
	for target, prefixes := range copyAutomationTargetArgPrefixes() {
		for _, prefix := range prefixes {
			if key == prefix {
				return target, true
			}
		}
	}
	return "", false
}

func copyAutomationTargetArgPrefixes() map[string][]string {
	return map[string][]string{
		copyAutomationTargetSeed: {
			"--fingerprint",
		},
		copyAutomationTargetIdentity: {
			"--fingerprint-brand",
			"--fingerprint-brand-version",
			"--fingerprint-platform",
			"--fingerprint-platform-version",
		},
		copyAutomationTargetLocale: {
			"--lang",
			"--accept-lang",
			"--timezone",
		},
		copyAutomationTargetScreen: {
			"--window-size",
		},
		copyAutomationTargetHardware: {
			"--fingerprint-hardware-concurrency",
		},
		copyAutomationTargetNetwork: {
			"--webrtc-ip-handling-policy",
			"--disable-non-proxied-udp",
			"--disable-spoofing",
		},
	}
}
