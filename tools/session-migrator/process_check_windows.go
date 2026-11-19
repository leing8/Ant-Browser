//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	errorSharingViolation = syscall.Errno(32)
	errorLockViolation    = syscall.Errno(33)
	th32csSnapProcess     = 0x00000002
)

var (
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
)

type processEntry32W struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [260]uint16
}

// isFileLockedByOtherProcess 通过零共享只读句柄检测文件是否正被其他进程占用（不会修改文件内容或时间戳）。
func isFileLockedByOtherProcess(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	handle, err := syscall.CreateFile(
		ptr,
		syscall.GENERIC_READ,
		0, // dwShareMode = 0: 若任意其他进程已打开此文件，立即返回 ERROR_SHARING_VIOLATION
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if err == errorSharingViolation || err == errorLockViolation {
			return true, nil
		}
		return false, err
	}
	_ = syscall.CloseHandle(handle)
	return false, nil
}

// checkProfileDirInUse 检查指定浏览器实例目录是否正被运行中的 Chromium 占用。
func checkProfileDirInUse(userDataDir string) (bool, string) {
	candidates := []string{
		filepath.Join(userDataDir, "Default", "Network", "Cookies"),
		filepath.Join(userDataDir, "Default", "Cookies"),
		filepath.Join(userDataDir, "Default", "Local Storage", "leveldb", "LOCK"),
		filepath.Join(userDataDir, "Default", "Session Storage", "LOCK"),
		filepath.Join(userDataDir, "Default", "LOCK"),
		filepath.Join(userDataDir, "lockfile"),
	}
	for _, path := range candidates {
		locked, err := isFileLockedByOtherProcess(path)
		if err == nil && locked {
			rel, relErr := filepath.Rel(userDataDir, path)
			if relErr != nil {
				rel = filepath.Base(path)
			}
			return true, rel
		}
	}
	return false, ""
}

// listRunningAntBrowserProcesses 列出当前系统中正在运行的 Ant Browser 主程序进程名。
func listRunningAntBrowserProcesses() []string {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return nil
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))
	r1, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return nil
	}

	var found []string
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "ant-chrome.exe" || lower == "ant-chrome-dev.exe" {
			found = append(found, fmt.Sprintf("%s (PID %d)", name, entry.ProcessID))
		}
		r1, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r1 == 0 {
			break
		}
	}
	return found
}
