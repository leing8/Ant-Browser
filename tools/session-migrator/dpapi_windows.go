//go:build windows

// dpapi_windows.go 通过原生 Windows crypt32.dll / kernel32.dll 系统调用实现 DPAPI 加解密，
// 负责读写 Chromium Local State 中的 os_crypt.encrypted_key（免 CGO、免外部 DLL 依赖）及控制控制台密码隐藏。
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	// cryptProtectUIForbidden 禁止 DPAPI 弹出任何 Windows UI 交互窗口，确保离线批处理不阻塞。
	cryptProtectUIForbidden = 0x1
	// dpapiPrefix 是 Chromium Windows 在 Base64 解码后的 encrypted_key 头部写入的固定 5 字节标识。
	dpapiPrefix = "DPAPI"
)

var (
	modCrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
	modKernel32            = syscall.NewLazyDLL("kernel32.dll")
	procLocalFree          = modKernel32.NewProc("LocalFree")
	procGetConsoleMode     = modKernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = modKernel32.NewProc("SetConsoleMode")
)

// dataBlob 对应 Win32 CRYPTOAPI_BLOB (DATA_BLOB) 结构体布局。
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapiUnprotect 调用 Windows CryptUnprotectData 使用当前登录用户的 DPAPI 主密钥解包密文。
func dpapiUnprotect(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("DPAPI 密文为空")
	}
	inBlob := dataBlob{
		cbData: uint32(len(ciphertext)),
		pbData: &ciphertext[0],
	}
	var outBlob dataBlob
	r1, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	runtime.KeepAlive(ciphertext)
	if r1 == 0 {
		return nil, fmt.Errorf("Windows DPAPI 解密失败（必须在导出该数据的同一台电脑和同一 Windows 用户下运行）: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	out := make([]byte, outBlob.cbData)
	if outBlob.cbData > 0 {
		copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	}
	return out, nil
}

// dpapiProtect 调用 Windows CryptProtectData 使用当前登录用户的 DPAPI 主密钥保护明文。
func dpapiProtect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("DPAPI 明文为空")
	}
	inBlob := dataBlob{
		cbData: uint32(len(plaintext)),
		pbData: &plaintext[0],
	}
	var outBlob dataBlob
	r1, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	runtime.KeepAlive(plaintext)
	if r1 == 0 {
		return nil, fmt.Errorf("Windows DPAPI 加密失败: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	out := make([]byte, outBlob.cbData)
	if outBlob.cbData > 0 {
		copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	}
	return out, nil
}

// localStateKeyInfo 封装从 Chromium Local State 中提取的 Windows DPAPI 密钥与诊断标志。
type localStateKeyInfo struct {
	AESKey            []byte
	HasAppBoundKey    bool
	LocalStateMissing bool
}

// readLocalStateDPAPIKey 读取 Chromium Local State 中的 DPAPI 主密钥（32 字节 AES-256-GCM 密钥）。
func readLocalStateDPAPIKey(userDataDir string) (*localStateKeyInfo, error) {
	localStatePath := filepath.Join(userDataDir, "Local State")
	rawBytes, err := os.ReadFile(localStatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &localStateKeyInfo{LocalStateMissing: true}, nil
		}
		return nil, fmt.Errorf("读取 Local State 失败: %w", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(rawBytes, &doc); err != nil {
		return nil, fmt.Errorf("解析 Local State JSON 失败: %w", err)
	}

	info := &localStateKeyInfo{}
	osCrypt, ok := doc["os_crypt"].(map[string]any)
	if !ok || osCrypt == nil {
		return info, nil
	}
	if appBound, ok := osCrypt["app_bound_encrypted_key"].(string); ok && strings.TrimSpace(appBound) != "" {
		info.HasAppBoundKey = true
	}

	encKeyB64, ok := osCrypt["encrypted_key"].(string)
	if !ok || strings.TrimSpace(encKeyB64) == "" {
		return info, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encKeyB64))
	if err != nil {
		return nil, fmt.Errorf("解码 os_crypt.encrypted_key 失败: %w", err)
	}
	if len(decoded) <= len(dpapiPrefix) || string(decoded[:len(dpapiPrefix)]) != dpapiPrefix {
		return nil, fmt.Errorf("不支持的 os_crypt.encrypted_key 前缀（期望 DPAPI）")
	}

	aesKey, err := dpapiUnprotect(decoded[len(dpapiPrefix):])
	if err != nil {
		return nil, err
	}
	if len(aesKey) != 32 {
		zeroBytes(aesKey)
		return nil, fmt.Errorf("解包后的 os_crypt 密钥长度异常: %d 字节（期望 32 字节）", len(aesKey))
	}
	info.AESKey = aesKey
	return info, nil
}

// ensureTargetLocalStateDPAPIKey 确保目标实例目录拥有当前 Windows 用户可解密的 Local State DPAPI 密钥。
// 如果目标实例已有合法的本机 DPAPI 密钥，则原样复用（避免破坏目标实例内可能存在的其他加密数据）；
// 如果是新实例或来自其他电脑的失效密钥，则生成新 32 字节密钥并用本机 DPAPI 封装写入 Local State。
func ensureTargetLocalStateDPAPIKey(userDataDir string) (aesKey []byte, reused bool, err error) {
	if err := os.MkdirAll(userDataDir, 0o755); err != nil {
		return nil, false, fmt.Errorf("创建目标实例目录失败: %w", err)
	}
	localStatePath := filepath.Join(userDataDir, "Local State")

	var doc map[string]any
	if rawBytes, readErr := os.ReadFile(localStatePath); readErr == nil {
		if jsonErr := json.Unmarshal(rawBytes, &doc); jsonErr == nil && doc != nil {
			if osCrypt, ok := doc["os_crypt"].(map[string]any); ok && osCrypt != nil {
				if encKeyB64, ok := osCrypt["encrypted_key"].(string); ok && strings.TrimSpace(encKeyB64) != "" {
					if decoded, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(encKeyB64)); decErr == nil &&
						len(decoded) > len(dpapiPrefix) && string(decoded[:len(dpapiPrefix)]) == dpapiPrefix {
						if existingKey, unprotErr := dpapiUnprotect(decoded[len(dpapiPrefix):]); unprotErr == nil && len(existingKey) == 32 {
							return existingKey, true, nil
						} else if existingKey != nil {
							zeroBytes(existingKey)
						}
					}
				}
			}
		} else {
			doc = nil
		}
	} else if !os.IsNotExist(readErr) {
		return nil, false, fmt.Errorf("读取目标 Local State 失败: %w", readErr)
	}

	if doc == nil {
		doc = make(map[string]any)
	}
	osCrypt, ok := doc["os_crypt"].(map[string]any)
	if !ok || osCrypt == nil {
		osCrypt = make(map[string]any)
		doc["os_crypt"] = osCrypt
	}

	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, false, fmt.Errorf("生成新 AES 密钥失败: %w", err)
	}

	protected, err := dpapiProtect(newKey)
	if err != nil {
		zeroBytes(newKey)
		return nil, false, err
	}

	wrapped := make([]byte, 0, len(dpapiPrefix)+len(protected))
	wrapped = append(wrapped, []byte(dpapiPrefix)...)
	wrapped = append(wrapped, protected...)

	osCrypt["encrypted_key"] = base64.StdEncoding.EncodeToString(wrapped)
	osCrypt["audit_enabled"] = true
	// 移除可能来自旧机器的失效 App-Bound 密钥，避免 Chromium 启动误判
	delete(osCrypt, "app_bound_encrypted_key")

	encodedJSON, err := json.Marshal(doc)
	if err != nil {
		zeroBytes(newKey)
		return nil, false, fmt.Errorf("序列化 Local State 失败: %w", err)
	}

	if err := atomicWriteFile(localStatePath, encodedJSON, 0o600); err != nil {
		zeroBytes(newKey)
		return nil, false, fmt.Errorf("写入目标 Local State 失败: %w", err)
	}
	return newKey, false, nil
}

// setConsoleEcho 控制 Windows 控制台密码输入是否回显。
func setConsoleEcho(enable bool) (restore func()) {
	const enableEchoInput = 0x0004
	handle := syscall.Handle(os.Stdin.Fd())
	var mode uint32
	r1, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r1 == 0 {
		return func() {}
	}
	oldMode := mode
	if enable {
		mode |= enableEchoInput
	} else {
		mode &^= enableEchoInput
	}
	_, _, _ = procSetConsoleMode.Call(uintptr(handle), uintptr(mode))
	return func() {
		_, _, _ = procSetConsoleMode.Call(uintptr(handle), uintptr(oldMode))
	}
}
