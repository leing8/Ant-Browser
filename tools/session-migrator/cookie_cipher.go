// cookie_cipher.go 实现与操作系统解耦的 Chromium Cookies 核心加解密算法层：
// 1. Windows 路径：v10/v11 AES-256-GCM（12 字节随机 Nonce + schema v24 32 字节 SHA256(host_key) 前缀）；
// 2. macOS 路径：PBKDF2-HMAC-SHA1（salt="saltysalt", iter=1003, 16 字节密钥）+ v10 AES-128-CBC（16 空格 IV + PKCS#7 + v24 域名前缀）。
// 将纯算法与平台密钥获取拆开，确保在 Windows 上也能完整单元测试 macOS 加密逻辑与跨系统往返。
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// 以下三个常量严格对应 Chromium 源码 components/os_crypt/sync/os_crypt_mac.mm：
	// macOS 端统一使用 "saltysalt" 与 1003 次迭代派生 16 字节 AES-128 密钥（注意 Linux 为 1 次迭代，不可混用）。
	macOSPBKDF2Salt       = "saltysalt"
	macOSPBKDF2Iterations = 1003
	macOSAESKeyLen        = 16
)

// macOSStaticIV 是 Chromium macOS AES-128-CBC 使用的固定 16 字节空格初始化向量（0x20 * 16）。
var macOSStaticIV = []byte("                ")

// cookieCryptoOptions 封装调用方可选覆盖的平台加密参数（目前供 macOS Keychain 显式覆写）。
type cookieCryptoOptions struct {
	KeychainService  string
	KeychainPassword string
}

// cookieCipher 抽象不同操作系统上 Chromium Cookies 的加解密实现：
// - Windows: Local State DPAPI 封装的 32 字节密钥 + AES-256-GCM (v10) + v24 SHA256(host_key)
// - macOS:   Keychain Safe Storage 派生的 16 字节密钥 (PBKDF2-SHA1, salt="saltysalt", iter=1003) + AES-128-CBC (v10, IV=16空格) + v24 SHA256(host_key)
type cookieCipher interface {
	DecryptCookie(encVal []byte, hostKey string, schemaVer int) (value string, hashMatched bool, skippedV20 bool, unknownPrefix bool, err error)
	EncryptCookie(hostKey string, value string) ([]byte, error)
	HasAppBoundKey() bool
	Notice() string
	Close()
}

// ============================================================================
// Windows AES-256-GCM Cipher（纯算法层，不依赖平台 build tag，便于跨平台单测）
// ============================================================================

// windowsGCMCookieCipher 实现 Windows Chromium 的 v10/v11 AES-256-GCM 加解密器。
type windowsGCMCookieCipher struct {
	key            []byte
	aead           cipher.AEAD
	hasAppBoundKey bool
	legacyDecrypt  func([]byte) ([]byte, error)
}

// newWindowsGCMCookieCipher 构造 Windows Cookie 加解密器，内部拷贝密钥并在 Close 时清零内存。
func newWindowsGCMCookieCipher(key []byte, hasAppBoundKey bool, legacyDecrypt func([]byte) ([]byte, error)) (*windowsGCMCookieCipher, error) {
	c := &windowsGCMCookieCipher{
		hasAppBoundKey: hasAppBoundKey,
		legacyDecrypt:  legacyDecrypt,
	}
	if len(key) > 0 {
		if len(key) != 32 {
			return nil, fmt.Errorf("Windows AES-256-GCM 密钥长度异常: %d 字节", len(key))
		}
		keyCopy := append([]byte(nil), key...)
		block, err := aes.NewCipher(keyCopy)
		if err != nil {
			zeroBytes(keyCopy)
			return nil, fmt.Errorf("初始化 AES-256 解密器失败: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			zeroBytes(keyCopy)
			return nil, fmt.Errorf("初始化 AES-256-GCM 失败: %w", err)
		}
		c.key = keyCopy
		c.aead = aead
	}
	return c, nil
}

// DecryptCookie 解密 Windows 下的 Cookie 密文：支持 v10/v11 AES-256-GCM、识别 v20 App-Bound 密文，
// 并对旧版无前缀密文兜底尝试原始 DPAPI 解密。
func (c *windowsGCMCookieCipher) DecryptCookie(encVal []byte, hostKey string, schemaVer int) (string, bool, bool, bool, error) {
	if len(encVal) < 3 {
		return "", false, false, true, nil
	}
	prefix := string(encVal[:3])
	switch prefix {
	case chromiumV10Prefix, chromiumV11Prefix:
		if c.aead == nil {
			return "", false, false, false, errors.New("存在加密 Cookie，但缺少可用的 Local State DPAPI 密钥")
		}
		plain, matched, err := decryptChromiumV10GCM(c.aead, encVal, hostKey, schemaVer)
		return plain, matched, false, false, err
	case chromiumV20Prefix:
		return "", false, true, false, nil
	default:
		if c.legacyDecrypt != nil {
			if plainBytes, err := c.legacyDecrypt(encVal); err == nil {
				defer zeroBytes(plainBytes)
				return string(plainBytes), true, false, false, nil
			}
		}
		return "", false, false, true, nil
	}
}

// EncryptCookie 使用本机 AES-256-GCM 密钥按 Chromium v24 格式重加密单条 Cookie。
func (c *windowsGCMCookieCipher) EncryptCookie(hostKey string, value string) ([]byte, error) {
	if c.aead == nil {
		return nil, errors.New("AES-256-GCM 加密器未初始化")
	}
	return encryptChromiumV10GCM(c.aead, hostKey, value)
}

// HasAppBoundKey 返回源 Local State 是否包含 Windows App-Bound 加密密钥。
func (c *windowsGCMCookieCipher) HasAppBoundKey() bool { return c.hasAppBoundKey }

// Notice 返回平台加解密附加提示（Windows 路径默认为空）。
func (c *windowsGCMCookieCipher) Notice() string { return "" }

// Close 覆写清零内存中缓存的 AES-256 密钥字节。
func (c *windowsGCMCookieCipher) Close() {
	zeroBytes(c.key)
	c.key = nil
}

// decryptChromiumV10GCM 解密单条 Windows v10/v11 AES-256-GCM Cookie；
// 当 schemaVer >= 24 时校验并剥离明文头部 32 字节 SHA256(host_key)。
func decryptChromiumV10GCM(aead cipher.AEAD, encVal []byte, hostKey string, schemaVer int) (value string, hashMatched bool, err error) {
	if len(encVal) < 3+gcmNonceSize+aead.Overhead() {
		return "", false, errors.New("v10 密文长度不足")
	}
	nonce := encVal[3 : 3+gcmNonceSize]
	ciphertext := encVal[3+gcmNonceSize:]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", false, err
	}
	defer zeroBytes(plain)

	if schemaVer >= 24 {
		expectedHash := sha256.Sum256([]byte(hostKey))
		if len(plain) >= sha256.Size && bytes.Equal(plain[:sha256.Size], expectedHash[:]) {
			return string(plain[sha256.Size:]), true, nil
		}
		return string(plain), false, nil
	}
	return string(plain), true, nil
}

// encryptChromiumV10GCM 按 Chromium v24 规范加密单条 Cookie：
// 输出格式为 "v10" || 12字节随机Nonce || AES-256-GCM(SHA256(host_key) || value)。
func encryptChromiumV10GCM(aead cipher.AEAD, hostKey string, value string) ([]byte, error) {
	hostHash := sha256.Sum256([]byte(hostKey))
	plain := make([]byte, sha256.Size+len(value))
	copy(plain[:sha256.Size], hostHash[:])
	copy(plain[sha256.Size:], value)
	defer zeroBytes(plain)

	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 Cookie 随机数失败: %w", err)
	}
	sealed := aead.Seal(nil, nonce, plain, nil)

	out := make([]byte, 0, len(chromiumV10Prefix)+len(nonce)+len(sealed))
	out = append(out, []byte(chromiumV10Prefix)...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// ============================================================================
// macOS AES-128-CBC Cipher（纯算法层，严格遵循 Chromium os_crypt_mac.mm + v24）
// ============================================================================

// macOSCBCCookieCipher 实现 macOS Chromium 的 v10 AES-128-CBC 加解密器。
type macOSCBCCookieCipher struct {
	key    []byte
	block  cipher.Block
	notice string
}

// deriveMacOSCookieKey 按 Chromium os_crypt_mac.mm 规范通过 PBKDF2-HMAC-SHA1 派生 16 字节 AES-128 密钥。
func deriveMacOSCookieKey(keychainSecret string) []byte {
	return pbkdf2.Key([]byte(keychainSecret), []byte(macOSPBKDF2Salt), macOSPBKDF2Iterations, macOSAESKeyLen, sha1.New)
}

// newMacOSCBCCookieCipher 根据 macOS Keychain Safe Storage 原始密码构造 AES-128-CBC 加解密器。
func newMacOSCBCCookieCipher(keychainSecret string, notice string) (*macOSCBCCookieCipher, error) {
	if keychainSecret == "" {
		return nil, errors.New("macOS Keychain Safe Storage 密钥为空")
	}
	key := deriveMacOSCookieKey(keychainSecret)
	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("初始化 macOS AES-128 加密器失败: %w", err)
	}
	return &macOSCBCCookieCipher{
		key:    key,
		block:  block,
		notice: notice,
	}, nil
}

// DecryptCookie 解密 macOS Chromium 的 v10/v11 AES-128-CBC 密文（16 空格 IV + PKCS#7），
// 并在 schemaVer >= 24 时校验和剥离 32 字节 SHA256(host_key) 域名前缀。
func (c *macOSCBCCookieCipher) DecryptCookie(encVal []byte, hostKey string, schemaVer int) (string, bool, bool, bool, error) {
	if len(encVal) < 3 {
		return "", false, false, true, nil
	}
	prefix := string(encVal[:3])
	switch prefix {
	case chromiumV10Prefix, chromiumV11Prefix:
		ct := encVal[3:]
		if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
			return "", false, false, false, fmt.Errorf("macOS v10 密文长度不是 16 字节对齐: %d", len(ct))
		}
		decrypted := make([]byte, len(ct))
		defer zeroBytes(decrypted)
		mode := cipher.NewCBCDecrypter(c.block, macOSStaticIV)
		mode.CryptBlocks(decrypted, ct)

		plain, err := pkcs7Unpad(decrypted, aes.BlockSize)
		if err != nil {
			return "", false, false, false, fmt.Errorf("macOS AES-128-CBC 解密失败（Keychain 密钥不匹配或数据损坏）: %w", err)
		}
		if schemaVer >= 24 {
			expectedHash := sha256.Sum256([]byte(hostKey))
			if len(plain) >= sha256.Size && bytes.Equal(plain[:sha256.Size], expectedHash[:]) {
				return string(plain[sha256.Size:]), true, false, false, nil
			}
			return string(plain), false, false, false, nil
		}
		return string(plain), true, false, false, nil
	case chromiumV20Prefix:
		return "", false, true, false, nil
	default:
		return "", false, false, true, nil
	}
}

// EncryptCookie 按 macOS Chromium v24 规范加密单条 Cookie：
// 输出格式为 "v10" || AES-128-CBC(PKCS7(SHA256(host_key) || value))。
func (c *macOSCBCCookieCipher) EncryptCookie(hostKey string, value string) ([]byte, error) {
	hostHash := sha256.Sum256([]byte(hostKey))
	plain := make([]byte, sha256.Size+len(value))
	copy(plain[:sha256.Size], hostHash[:])
	copy(plain[sha256.Size:], value)
	defer zeroBytes(plain)

	padded := pkcs7Pad(plain, aes.BlockSize)
	defer zeroBytes(padded)

	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(c.block, macOSStaticIV)
	mode.CryptBlocks(ct, padded)

	out := make([]byte, 0, len(chromiumV10Prefix)+len(ct))
	out = append(out, []byte(chromiumV10Prefix)...)
	out = append(out, ct...)
	return out, nil
}

// HasAppBoundKey 返回是否启用 App-Bound 加密（macOS 平台恒为 false）。
func (c *macOSCBCCookieCipher) HasAppBoundKey() bool { return false }

// Notice 返回 macOS 钥匙串条目选择或回退提示信息。
func (c *macOSCBCCookieCipher) Notice() string { return c.notice }

// Close 覆写清零内存中派生的 AES-128 密钥字节。
func (c *macOSCBCCookieCipher) Close() {
	zeroBytes(c.key)
	c.key = nil
}

// pkcs7Pad 对明文执行标准 PKCS#7 填充，确保长度为 AES 块大小（16 字节）的整数倍。
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

// pkcs7Unpad 严格校验并移除 PKCS#7 填充；若密钥错误通常会在此处快速失败。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("无效的 PKCS#7 块长度")
	}
	padLen := int(data[len(data)-1])
	if padLen <= 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("无效的 PKCS#7 填充字节")
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			return nil, errors.New("PKCS#7 填充校验失败")
		}
	}
	return data[:len(data)-padLen], nil
}

// zeroBytes 原地覆写敏感字节切片（密钥/明文缓冲区），降低敏感数据在内存中的驻留时间。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
