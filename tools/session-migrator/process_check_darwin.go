//go:build darwin

// process_check_darwin.go 实现 macOS 平台下的 Chromium 实例占用检测（SingletonLock + flock）
// 与 Ant Browser 主进程检查（pgrep）。
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// checkProfileDirInUse 在 macOS 上通过 SingletonLock 软链 PID 与 LevelDB flock 检查实例是否仍在运行。
func checkProfileDirInUse(userDataDir string) (bool, string) {
	// 1. Chromium 在 macOS/Linux 上于 userDataDir 创建 SingletonLock -> "<hostname>-<pid>"
	singletonLock := filepath.Join(userDataDir, "SingletonLock")
	if target, err := os.Readlink(singletonLock); err == nil {
		if idx := strings.LastIndex(target, "-"); idx >= 0 && idx+1 < len(target) {
			if pid, pErr := strconv.Atoi(strings.TrimSpace(target[idx+1:])); pErr == nil && pid > 0 {
				if killErr := syscall.Kill(pid, 0); killErr == nil || killErr == syscall.EPERM {
					return true, fmt.Sprintf("SingletonLock (PID %d)", pid)
				}
			}
		}
	}

	// 2. 检测 LevelDB LOCK 文件是否被 flock 独占占用
	for _, rel := range []string{
		"Default/Local Storage/leveldb/LOCK",
		"Default/Session Storage/LOCK",
		"Default/LOCK",
	} {
		lockPath := filepath.Join(userDataDir, filepath.FromSlash(rel))
		if isUnixFileFlocked(lockPath) {
			return true, rel
		}
	}
	return false, ""
}

// isUnixFileFlocked 使用非阻塞排他 flock 探测文件是否已被其他进程锁定，探测完立即释放。
func isUnixFileFlocked(path string) bool {
	if !fileExists(path) {
		return false
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err == syscall.EWOULDBLOCK || err == syscall.EAGAIN
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false
}

// listRunningAntBrowserProcesses 通过 macOS 内置 /usr/bin/pgrep 检测 Ant Browser 主程序是否正在运行。
func listRunningAntBrowserProcesses() []string {
	var found []string
	for _, procName := range []string{"ant-chrome", "ant-chrome-dev"} {
		out, err := exec.Command("/usr/bin/pgrep", "-x", procName).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			pid := strings.TrimSpace(line)
			if pid != "" {
				found = append(found, fmt.Sprintf("%s (PID %s)", procName, pid))
			}
		}
	}
	return found
}
