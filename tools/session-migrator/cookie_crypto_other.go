//go:build !windows && !darwin

// cookie_crypto_other.go 为暂未适配的操作系统（如 Linux）提供编译占位实现，确保交叉编译检查清晰报错。
package main

import "errors"

var errUnsupportedPlatform = errors.New("当前工具目前支持 Windows (DPAPI) 与 macOS (Keychain Safe Storage)")

// openExportCookieCipher 在非 Windows/macOS 平台直接返回不支持错误。
func openExportCookieCipher(_ string, _ *AppInstallation, _ cookieCryptoOptions, _ []sampleEncryptedCookie) (cookieCipher, error) {
	return nil, errUnsupportedPlatform
}

// ensureImportCookieCipher 在非 Windows/macOS 平台直接返回不支持错误。
func ensureImportCookieCipher(_ string, _ *AppInstallation, _ cookieCryptoOptions) (cookieCipher, bool, error) {
	return nil, false, errUnsupportedPlatform
}

// platformCryptoLabel 返回未支持平台占位标签。
func platformCryptoLabel() string {
	return "unsupported"
}

// setConsoleEcho 在非 Windows/macOS 平台为空操作。
func setConsoleEcho(_ bool) func() {
	return func() {}
}
