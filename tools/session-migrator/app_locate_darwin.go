//go:build darwin

// app_locate_darwin.go 实现 macOS 平台 Ant Browser 独立用户状态目录发现与 .app 路径自动重定向。
package main

import (
	"os"
	"path/filepath"
	"strings"
)

// platformCandidate 表示平台探测到的候选状态根目录及其来源说明。
type platformCandidate struct {
	path  string
	label string
}

// macUserStateRoot 返回 Ant Browser macOS 正式版使用的可写状态根目录：
// ~/Library/Application Support/ant-browser（与主项目 backend/internal/apppath/apppath.go 保持一致）。
func macUserStateRoot() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		home = strings.TrimSpace(os.Getenv("HOME"))
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "ant-browser")
}

// discoverPlatformReleaseCandidates 返回 macOS 正式版默认状态目录候选。
func discoverPlatformReleaseCandidates() []platformCandidate {
	var out []platformCandidate
	if stateRoot := macUserStateRoot(); stateRoot != "" {
		out = append(out, platformCandidate{
			path:  stateRoot,
			label: "正式版（macOS Application Support 用户状态目录）",
		})
	}
	return out
}

// normalizePlatformAppRoot 当 macOS 用户传入 Ant Browser.app 或 .app/Contents/MacOS 时，
// 自动重定向到 Ant Browser 实际写入数据的 ~/Library/Application Support/ant-browser 目录。
func normalizePlatformAppRoot(absRoot string) string {
	clean := filepath.Clean(absRoot)
	lower := strings.ToLower(filepath.ToSlash(clean))
	isBundle := strings.HasSuffix(lower, ".app") ||
		strings.HasSuffix(lower, ".app/contents") ||
		strings.HasSuffix(lower, ".app/contents/macos") ||
		strings.HasSuffix(lower, ".app/contents/resources") ||
		fileExists(filepath.Join(clean, "Contents", "MacOS", "ant-chrome"))
	if isBundle {
		if stateRoot := macUserStateRoot(); stateRoot != "" {
			return stateRoot
		}
	}
	return clean
}
