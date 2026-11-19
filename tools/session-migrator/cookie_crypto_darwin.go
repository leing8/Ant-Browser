//go:build darwin

// cookie_crypto_darwin.go 实现 macOS 平台通过系统钥匙串（/usr/bin/security）读写
// Chromium Safe Storage / Chrome Safe Storage 密钥的逻辑，使纯 Go 无 CGO 二进制即可完成 macOS 离线加解密。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// macKeychainTarget 表示 macOS 钥匙串中的一对通用密码（Service / Account）标识。
type macKeychainTarget struct {
	Service string
	Account string
}

var (
	macKeychainChromium = macKeychainTarget{Service: "Chromium Safe Storage", Account: "Chromium"}
	macKeychainChrome   = macKeychainTarget{Service: "Chrome Safe Storage", Account: "Chrome"}
)

// 进程级钥匙串密钥缓存：批量导出/导入数十个实例时只访问一次钥匙串，避免 macOS 连续弹出授权对话框。
var (
	macImportKeyCacheMu    sync.Mutex
	macImportKeyCacheBySvc = make(map[string]string)
	macImportNoticeBySvc   = make(map[string]string)
	macExportKeyCacheMu    sync.Mutex
	macExportKeyCacheBySvc = make(map[string]string)
)

// platformCryptoLabel 返回 macOS 平台的底层加密方式说明。
func platformCryptoLabel() string {
	return "macOS Keychain (Safe Storage) + AES-128-CBC"
}

// detectPreferredMacKeychainTarget 根据显式参数或 Ant Browser 的 chrome/ 目录内核类型，
// 自动决定优先使用的钥匙串项（Chromium.app -> Chromium Safe Storage；Google Chrome.app -> Chrome Safe Storage）。
func detectPreferredMacKeychainTarget(inst *AppInstallation, opts cookieCryptoOptions) macKeychainTarget {
	svc := strings.TrimSpace(opts.KeychainService)
	if svc != "" {
		if strings.EqualFold(svc, macKeychainChrome.Service) {
			return macKeychainChrome
		}
		if strings.EqualFold(svc, macKeychainChromium.Service) {
			return macKeychainChromium
		}
		return macKeychainTarget{Service: svc, Account: strings.TrimSuffix(svc, " Safe Storage")}
	}

	// 自动检测 Ant Browser 在 macOS 上使用的内核类型（Chromium.app vs Google Chrome.app）
	if inst != nil {
		chromeDir := filepath.Join(inst.AppRoot, "chrome")
		if dirExists(chromeDir) {
			hasChromium := false
			hasGoogleChrome := false
			_ = filepath.WalkDir(chromeDir, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					name := d.Name()
					if strings.EqualFold(name, "Chromium.app") {
						hasChromium = true
						return filepath.SkipDir
					}
					if strings.EqualFold(name, "Google Chrome.app") {
						hasGoogleChrome = true
						return filepath.SkipDir
					}
				}
				return nil
			})
			if hasGoogleChrome && !hasChromium {
				return macKeychainChrome
			}
		}
	}
	return macKeychainChromium
}

// readMacKeychainSecret 调用 macOS 内置 /usr/bin/security 工具读取指定 Safe Storage 密码。
func readMacKeychainSecret(target macKeychainTarget) (string, error) {
	// 1. 先按 service + account 精确查
	if target.Account != "" {
		cmd := exec.Command("/usr/bin/security", "find-generic-password", "-w", "-s", target.Service, "-a", target.Account)
		if out, err := cmd.Output(); err == nil {
			if secret := strings.TrimRight(string(out), "\r\n"); secret != "" {
				return secret, nil
			}
		}
	}
	// 2. 兜底仅按 service 查
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-w", "-s", target.Service)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("未在 macOS 钥匙串中找到 %q（%s）", target.Service, strings.TrimSpace(string(out)))
	}
	secret := strings.TrimRight(string(out), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("macOS 钥匙串项 %q 内容为空", target.Service)
	}
	return secret, nil
}

// createMacKeychainSecret 在全新 macOS 尚未创建对应 Safe Storage 时，生成与 Chromium 规范一致的随机密钥并写入登录钥匙串。
func createMacKeychainSecret(target macKeychainTarget) (string, error) {
	// 与 Chromium keychain_password_mac.mm 一致：16 字节随机数的标准 Base64 编码
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("生成 macOS 钥匙串随机密钥失败: %w", err)
	}
	secret := base64.StdEncoding.EncodeToString(raw)
	zeroBytes(raw)

	account := target.Account
	if account == "" {
		account = "Chromium"
	}
	// -A 允许本机应用访问（首次被 Chromium 读取时 macOS 可能弹窗，点击「始终允许」即可）
	cmd := exec.Command("/usr/bin/security", "add-generic-password",
		"-s", target.Service,
		"-a", account,
		"-w", secret,
		"-A",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("写入 macOS 钥匙串 %q 失败: %w (%s)", target.Service, err, strings.TrimSpace(string(out)))
	}
	return secret, nil
}

// readCachedMacExportSecret 带进程内缓存地读取导出阶段所需的钥匙串密码。
func readCachedMacExportSecret(target macKeychainTarget) (string, error) {
	key := strings.ToLower(target.Service)
	macExportKeyCacheMu.Lock()
	if cached, ok := macExportKeyCacheBySvc[key]; ok {
		macExportKeyCacheMu.Unlock()
		return cached, nil
	}
	macExportKeyCacheMu.Unlock()

	secret, err := readMacKeychainSecret(target)
	if err != nil {
		return "", err
	}
	macExportKeyCacheMu.Lock()
	macExportKeyCacheBySvc[key] = secret
	macExportKeyCacheMu.Unlock()
	return secret, nil
}

// openExportCookieCipher 为 macOS 导出流程挑选并验签正确的 Safe Storage 密钥。
// 利用 Chromium v24 的 SHA256(host_key) 对样本 Cookie 试解，自动区分 Chromium / Chrome / mock(peanuts)。
func openExportCookieCipher(_ string, inst *AppInstallation, opts cookieCryptoOptions, samples []sampleEncryptedCookie) (cookieCipher, error) {
	// 若显式传入明文密钥（如无头环境）
	if opts.KeychainPassword != "" {
		return newMacOSCBCCookieCipher(opts.KeychainPassword, "")
	}

	preferred := detectPreferredMacKeychainTarget(inst, opts)
	candidates := []macKeychainTarget{preferred}
	if !strings.EqualFold(preferred.Service, macKeychainChromium.Service) {
		candidates = append(candidates, macKeychainChromium)
	}
	if !strings.EqualFold(preferred.Service, macKeychainChrome.Service) {
		candidates = append(candidates, macKeychainChrome)
	}

	type secretCandidate struct {
		label  string
		secret string
	}
	var loaded []secretCandidate
	var errs []string

	for _, t := range candidates {
		sec, err := readCachedMacExportSecret(t)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		loaded = append(loaded, secretCandidate{label: t.Service, secret: sec})
	}
	// 始终保留 Chromium --use-mock-keychain 默认密码 "peanuts" 作为最后兜底
	loaded = append(loaded, secretCandidate{label: "mock-keychain(peanuts)", secret: "peanuts"})

	// 用真实样本 Cookie 验证哪一个钥匙串密钥能精确解出合法的 PKCS#7 与 v24 SHA256(host_key)
	if len(samples) > 0 {
		for _, cand := range loaded {
			c, err := newMacOSCBCCookieCipher(cand.secret, "")
			if err != nil {
				continue
			}
			allOK := true
			for _, s := range samples {
				_, hashMatched, skippedV20, unknownPrefix, decErr := c.DecryptCookie(s.EncVal, s.HostKey, s.SchemaVer)
				if decErr != nil || skippedV20 || unknownPrefix || (s.SchemaVer >= 24 && !hashMatched) {
					allOK = false
					break
				}
			}
			if allOK {
				return c, nil
			}
			c.Close()
		}
		// 若样本不带 v24 哈希（极老版本），退而求其次接受 PKCS#7 解密成功的候选
		for _, cand := range loaded {
			c, err := newMacOSCBCCookieCipher(cand.secret, "")
			if err != nil {
				continue
			}
			allOK := true
			for _, s := range samples {
				_, _, skippedV20, unknownPrefix, decErr := c.DecryptCookie(s.EncVal, s.HostKey, s.SchemaVer)
				if decErr != nil || skippedV20 || unknownPrefix {
					allOK = false
					break
				}
			}
			if allOK {
				return c, nil
			}
			c.Close()
		}
		return nil, fmt.Errorf("无法用本机 macOS 钥匙串（%s）解密该实例 Cookies，请确认已在钥匙串弹窗点选允许，或通过 --keychain-service 指定正确的 Safe Storage 名称（尝试详情: %s）",
			preferred.Service, strings.Join(errs, "; "))
	}

	// 无加密 Cookie 样本时，使用第一个成功读取的钥匙串密钥
	if len(loaded) > 0 {
		return newMacOSCBCCookieCipher(loaded[0].secret, "")
	}
	return nil, fmt.Errorf("读取 macOS 钥匙串失败: %s", strings.Join(errs, "; "))
}

// ensureImportCookieCipher 为 macOS 导入流程准备目标机 Safe Storage 密钥；
// 优先复用本机 Chromium 已有的钥匙串项，不存在时自动创建并附带一次性授权提示。
func ensureImportCookieCipher(userDataDir string, inst *AppInstallation, opts cookieCryptoOptions) (cookieCipher, bool, error) {
	if err := os.MkdirAll(userDataDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("创建目标实例目录失败: %w", err)
	}

	if opts.KeychainPassword != "" {
		c, err := newMacOSCBCCookieCipher(opts.KeychainPassword, "")
		return c, true, err
	}

	target := detectPreferredMacKeychainTarget(inst, opts)
	cacheKey := strings.ToLower(target.Service)

	// 批量导入 39 个实例时缓存已获取的钥匙串密码，避免 macOS 连续弹出 39 次授权框
	macImportKeyCacheMu.Lock()
	if cached, ok := macImportKeyCacheBySvc[cacheKey]; ok {
		notice := macImportNoticeBySvc[cacheKey]
		macImportKeyCacheMu.Unlock()
		c, err := newMacOSCBCCookieCipher(cached, notice)
		return c, true, err
	}
	macImportKeyCacheMu.Unlock()

	secret, err := readMacKeychainSecret(target)
	reused := true
	notice := ""
	if err != nil {
		// 全新 Mac 上尚未建立该钥匙串项：自动创建与 Chromium 兼容的 16 字节随机 Base64 密钥
		createdSecret, createErr := createMacKeychainSecret(target)
		if createErr != nil {
			return nil, false, fmt.Errorf("本机 macOS 钥匙串缺少 %q 且自动创建失败: %w（建议先在 Ant Browser 下载内核并启动关闭一次空白实例，让 Chromium 自动创建钥匙串后再重试导入）",
				target.Service, createErr)
		}
		secret = createdSecret
		reused = false
		notice = fmt.Sprintf("已在本机 macOS 钥匙串自动创建 %q；首次在 Ant Browser 启动实例时若 macOS 提示钥匙串授权，点击「始终允许」即可", target.Service)
	}

	macImportKeyCacheMu.Lock()
	macImportKeyCacheBySvc[cacheKey] = secret
	macImportNoticeBySvc[cacheKey] = notice
	macImportKeyCacheMu.Unlock()

	c, err := newMacOSCBCCookieCipher(secret, notice)
	return c, reused, err
}

// setConsoleEcho 在 macOS 终端通过 /bin/stty 隐藏/恢复密码输入回显。
func setConsoleEcho(enable bool) func() {
	flagArg := "-echo"
	if enable {
		flagArg = "echo"
	}
	cmd := exec.Command("/bin/stty", flagArg)
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return func() {}
	}
	return func() {
		restoreArg := "echo"
		if enable {
			restoreArg = "-echo"
		}
		rc := exec.Command("/bin/stty", restoreArg)
		rc.Stdin = os.Stdin
		_ = rc.Run()
	}
}
