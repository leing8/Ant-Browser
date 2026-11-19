//go:build !windows

package main

import "errors"

var errWindowsOnly = errors.New("当前工具基于 Windows DPAPI 离线加解密，请在 Windows 上运行")

type localStateKeyInfo struct {
	AESKey            []byte
	HasAppBoundKey    bool
	LocalStateMissing bool
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func readLocalStateDPAPIKey(userDataDir string) (*localStateKeyInfo, error) {
	return nil, errWindowsOnly
}

func ensureTargetLocalStateDPAPIKey(userDataDir string) ([]byte, bool, error) {
	return nil, false, errWindowsOnly
}

func setConsoleEcho(enable bool) func() {
	return func() {}
}
