//go:build !windows && !darwin

// app_locate_other.go 为其他平台提供安装目录自动发现的空实现。
package main

// platformCandidate 表示非 Windows/macOS 平台下的候选安装目录占位结构。
type platformCandidate struct {
	path  string
	label string
}

// discoverPlatformReleaseCandidates 在其他平台暂不执行注册表或固定目录扫描。
func discoverPlatformReleaseCandidates() []platformCandidate {
	return nil
}

// normalizePlatformAppRoot 原样返回目录路径。
func normalizePlatformAppRoot(absRoot string) string {
	return absRoot
}
