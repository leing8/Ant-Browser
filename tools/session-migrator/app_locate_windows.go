//go:build windows

// app_locate_windows.go 实现 Windows 平台 Ant Browser 正式版安装路径自动发现（读取卸载注册表与默认目录）。
package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// platformCandidate 表示平台探测到的候选安装根目录及其来源说明。
type platformCandidate struct {
	path  string
	label string
}

// discoverPlatformReleaseCandidates 按优先级枚举 Windows 正式版注册表记录及用户/系统默认安装路径。
func discoverPlatformReleaseCandidates() []platformCandidate {
	var out []platformCandidate

	if loc := readRegistryInstallLocation(syscall.HKEY_CURRENT_USER); loc != "" {
		out = append(out, platformCandidate{path: loc, label: "正式版（用户安装目录/注册表）"})
	}
	if loc := readRegistryInstallLocation(syscall.HKEY_LOCAL_MACHINE); loc != "" {
		out = append(out, platformCandidate{path: loc, label: "正式版（系统安装目录/注册表）"})
	}
	if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
		out = append(out, platformCandidate{
			path:  filepath.Join(localAppData, "Programs", "Ant Browser"),
			label: "正式版（默认用户安装目录）",
		})
	}
	if pf := strings.TrimSpace(os.Getenv("ProgramFiles")); pf != "" {
		out = append(out, platformCandidate{
			path:  filepath.Join(pf, "Ant Browser"),
			label: "正式版（历史 Program Files 目录）",
		})
	}
	return out
}

// readRegistryInstallLocation 读取 NSIS 安装器写入 HKCU/HKLM Uninstall\AntBrowser 的 InstallLocation 值。
func readRegistryInstallLocation(root syscall.Handle) string {
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Uninstall\AntBrowser`)
	if err != nil {
		return ""
	}
	var hKey syscall.Handle
	if err := syscall.RegOpenKeyEx(root, subKey, 0, syscall.KEY_READ, &hKey); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(hKey)

	valName, err := syscall.UTF16PtrFromString("InstallLocation")
	if err != nil {
		return ""
	}
	var valType uint32
	var bufLen uint32
	if err := syscall.RegQueryValueEx(hKey, valName, nil, &valType, nil, &bufLen); err != nil || bufLen == 0 {
		return ""
	}
	buf := make([]uint16, bufLen/2+1)
	if err := syscall.RegQueryValueEx(hKey, valName, nil, &valType, (*byte)(unsafe.Pointer(&buf[0])), &bufLen); err != nil {
		return ""
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf))
}

// normalizePlatformAppRoot 在 Windows 下数据目录直接位于安装目录内，无需重定向。
func normalizePlatformAppRoot(absRoot string) string {
	return absRoot
}
