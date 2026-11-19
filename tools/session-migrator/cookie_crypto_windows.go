//go:build windows

// cookie_crypto_windows.go 提供 Windows 平台的 Cookie 加解密器装配入口，
// 将 Local State DPAPI 密钥解包/生成与 windowsGCMCookieCipher 对接。
package main

// openExportCookieCipher 为导出流程打开源实例的 Windows DPAPI + AES-256-GCM 解密器。
func openExportCookieCipher(userDataDir string, _ *AppInstallation, _ cookieCryptoOptions, _ []sampleEncryptedCookie) (cookieCipher, error) {
	keyInfo, err := readLocalStateDPAPIKey(userDataDir)
	if err != nil {
		return nil, err
	}
	if keyInfo.AESKey != nil {
		defer zeroBytes(keyInfo.AESKey)
	}
	return newWindowsGCMCookieCipher(keyInfo.AESKey, keyInfo.HasAppBoundKey, dpapiUnprotect)
}

// ensureImportCookieCipher 为导入流程准备目标实例的本机 Windows DPAPI 密钥与加密器。
func ensureImportCookieCipher(userDataDir string, _ *AppInstallation, _ cookieCryptoOptions) (cookieCipher, bool, error) {
	aesKey, reused, err := ensureTargetLocalStateDPAPIKey(userDataDir)
	if err != nil {
		return nil, false, err
	}
	defer zeroBytes(aesKey)

	c, err := newWindowsGCMCookieCipher(aesKey, false, dpapiUnprotect)
	if err != nil {
		return nil, reused, err
	}
	return c, reused, nil
}

// platformCryptoLabel 返回当前运行平台使用的底层加密机制名称（用于日志与摘要展示）。
func platformCryptoLabel() string {
	return "Windows DPAPI + AES-256-GCM"
}
