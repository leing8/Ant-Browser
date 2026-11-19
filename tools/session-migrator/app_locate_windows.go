//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type platformCandidate struct {
	path  string
	label string
}

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
