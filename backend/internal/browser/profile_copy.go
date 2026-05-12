package browser

import (
	"ant-chrome/backend/internal/logger"
	"fmt"
	"math/rand"
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

// Copy 复制实例配置（保留所有指纹配置，但生成新的指纹种子）
func (m *Manager) Copy(profileId string, newName string) (*Profile, error) {
	log := logger.New("Browser")
	m.InitData()
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if m.Config.App.MaxProfileLimit > 0 && len(m.Profiles) >= m.Config.App.MaxProfileLimit {
		log.Error("复制实例失败: 达到数量上限", logger.F("limit", m.Config.App.MaxProfileLimit))
		return nil, newProfileLimitExceededError(m.Config.App.MaxProfileLimit, "复制实例")
	}

	src, exists := m.Profiles[profileId]
	if !exists {
		log.Error("源实例不存在", logger.F("profile_id", profileId))
		return nil, fmt.Errorf("profile not found")
	}

	now := time.Now().Format(time.RFC3339)
	newId := uuid.NewString()

	profileName := strings.TrimSpace(newName)
	if profileName == "" {
		profileName = src.ProfileName + " (副本)"
	}

	profile := &Profile{
		ProfileId:          newId,
		ProfileName:        profileName,
		UserDataDir:        newId,
		CoreId:             normalizeProfileCoreID(src.CoreId),
		FingerprintArgs:    copyFingerprintArgsWithNewSeed(src.FingerprintArgs),
		ProxyId:            src.ProxyId,
		ProxyConfig:        src.ProxyConfig,
		ProxyBindSourceID:  src.ProxyBindSourceID,
		ProxyBindSourceURL: src.ProxyBindSourceURL,
		ProxyBindName:      src.ProxyBindName,
		ProxyBindUpdatedAt: src.ProxyBindUpdatedAt,
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

	if m.Config.App.MaxProfileLimit > 0 && len(m.Profiles)+count > m.Config.App.MaxProfileLimit {
		log.Error("批量复制实例失败: 超出数量上限",
			logger.F("limit", m.Config.App.MaxProfileLimit),
			logger.F("current", len(m.Profiles)),
			logger.F("requested", count))
		return nil, newProfileLimitExceededError(m.Config.App.MaxProfileLimit, "批量复制实例")
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
			FingerprintArgs:    copyFingerprintArgsWithNewSeed(src.FingerprintArgs),
			ProxyId:            src.ProxyId,
			ProxyConfig:        src.ProxyConfig,
			ProxyBindSourceID:  src.ProxyBindSourceID,
			ProxyBindSourceURL: src.ProxyBindSourceURL,
			ProxyBindName:      src.ProxyBindName,
			ProxyBindUpdatedAt: src.ProxyBindUpdatedAt,
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
