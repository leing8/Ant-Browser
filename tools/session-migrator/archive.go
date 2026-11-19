// archive.go 实现 .antsess 迁移包的封装、读取与可选加密（scrypt + AES-256-GCM）。
// 外层为标准 ZIP，包含明文摘要 manifest.json 与内层载荷（加密模式为 payload.enc + payload.enc.json，
// 明文自用模式为 payload.zip）；所有敏感 Cookie、存储、指纹与代理凭据均只保存在内层载荷中。
package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	archiveManifestEntry  = "manifest.json"
	archivePlainPayload   = "payload.zip"
	archiveEncPayloadMeta = "payload.enc.json"
	archiveEncPayloadData = "payload.enc"
	archiveKDFName        = "scrypt-aes256gcm-v1"
	minPasswordRunes      = 4
)

// encryptedPayloadMeta 记录加密载荷的 KDF 算法、随机盐与 AES-GCM Nonce。
type encryptedPayloadMeta struct {
	Format string `json:"format"`
	KDF    string `json:"kdf"`
	Salt   string `json:"salt"`
	Nonce  string `json:"nonce"`
}

// deriveArchiveKey 使用 scrypt (N=32768, r=8, p=1) 从用户密码与 32 字节随机盐派生 AES-256 密钥。
func deriveArchiveKey(password string, salt []byte) ([]byte, error) {
	if len([]rune(password)) < minPasswordRunes {
		return nil, fmt.Errorf("密码至少需要 %d 个字符（若不想加密请显式选择不设密码）", minPasswordRunes)
	}
	return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
}

// writeSessionArchive 将 manifest 与内层 payloadZipBytes 打包为外层 .antsess 文件（支持可选密码加密）。
func writeSessionArchive(outputPath string, manifest ArchiveManifest, payloadZipBytes []byte, password string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	tmpPath := outputPath + fmt.Sprintf(".migrator.%d.tmp", os.Getpid())
	_ = os.Remove(tmpPath)

	outFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建迁移包文件失败: %w", err)
	}
	zw := zip.NewWriter(outFile)

	writeErr := func() error {
		if password != "" {
			manifest.Encrypted = true
			manifest.KDF = archiveKDFName
		} else {
			manifest.Encrypted = false
			manifest.KDF = ""
		}

		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("序列化 manifest 失败: %w", err)
		}
		mw, err := zw.Create(archiveManifestEntry)
		if err != nil {
			return err
		}
		if _, err := mw.Write(manifestBytes); err != nil {
			return err
		}

		if password == "" {
			// 未加密模式：直接以 Store 存放已经压缩过的内层 payload.zip
			hdr := &zip.FileHeader{Name: archivePlainPayload, Method: zip.Store}
			pw, err := zw.CreateHeader(hdr)
			if err != nil {
				return err
			}
			_, err = pw.Write(payloadZipBytes)
			return err
		}

		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("生成加密盐失败: %w", err)
		}
		key, err := deriveArchiveKey(password, salt)
		if err != nil {
			return err
		}
		defer zeroBytes(key)

		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("生成随机数失败: %w", err)
		}

		aad := []byte(archiveFormat + ":v1")
		ciphertext := gcm.Seal(nil, nonce, payloadZipBytes, aad)

		metaBytes, err := json.MarshalIndent(encryptedPayloadMeta{
			Format: archiveFormat,
			KDF:    archiveKDFName,
			Salt:   base64.RawStdEncoding.EncodeToString(salt),
			Nonce:  base64.RawStdEncoding.EncodeToString(nonce),
		}, "", "  ")
		if err != nil {
			return err
		}
		ewMeta, err := zw.Create(archiveEncPayloadMeta)
		if err != nil {
			return err
		}
		if _, err := ewMeta.Write(metaBytes); err != nil {
			return err
		}

		hdr := &zip.FileHeader{Name: archiveEncPayloadData, Method: zip.Store}
		ewData, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = ewData.Write(ciphertext)
		return err
	}()

	closeZipErr := zw.Close()
	closeFileErr := outFile.Close()
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return writeErr
	}
	if closeZipErr != nil {
		_ = os.Remove(tmpPath)
		return closeZipErr
	}
	if closeFileErr != nil {
		_ = os.Remove(tmpPath)
		return closeFileErr
	}
	if err := atomicReplaceFile(tmpPath, outputPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("保存迁移包失败: %w", err)
	}
	return nil
}

// readArchiveManifest 读取迁移包公开摘要（无需密码）。
func readArchiveManifest(archivePath string) (*ArchiveManifest, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("打开迁移包失败: %w", err)
	}
	defer zr.Close()

	data, err := readZipEntryBytes(zr.File, archiveManifestEntry)
	if err != nil {
		return nil, fmt.Errorf("读取 manifest.json 失败（可能不是有效的迁移包）: %w", err)
	}
	var m ArchiveManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("解析 manifest.json 失败: %w", err)
	}
	if m.Format != archiveFormat || m.Version != archiveVersion {
		return nil, fmt.Errorf("不支持的迁移包格式: %s (v%d)", m.Format, m.Version)
	}
	return &m, nil
}

// openSessionArchivePayload 解密/读取外层迁移包并打开内层 ZIP 载荷。
func openSessionArchivePayload(archivePath string, password string) (*ArchiveManifest, *zip.Reader, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("打开迁移包失败: %w", err)
	}
	defer zr.Close()

	manifestBytes, err := readZipEntryBytes(zr.File, archiveManifestEntry)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 manifest.json 失败: %w", err)
	}
	var manifest ArchiveManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, nil, fmt.Errorf("解析 manifest.json 失败: %w", err)
	}
	if manifest.Format != archiveFormat || manifest.Version != archiveVersion {
		return nil, nil, fmt.Errorf("不支持的迁移包格式: %s (v%d)", manifest.Format, manifest.Version)
	}

	var payloadBytes []byte
	if !manifest.Encrypted {
		payloadBytes, err = readZipEntryBytes(zr.File, archivePlainPayload)
		if err != nil {
			return nil, nil, fmt.Errorf("读取未加密载荷失败: %w", err)
		}
	} else {
		if password == "" {
			return nil, nil, fmt.Errorf("该迁移包已加密，请提供导出时设置的密码")
		}
		metaBytes, err := readZipEntryBytes(zr.File, archiveEncPayloadMeta)
		if err != nil {
			return nil, nil, fmt.Errorf("读取加密元数据失败: %w", err)
		}
		var meta encryptedPayloadMeta
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			return nil, nil, fmt.Errorf("解析加密元数据失败: %w", err)
		}
		if meta.Format != archiveFormat || meta.KDF != archiveKDFName {
			return nil, nil, fmt.Errorf("不支持的加密格式: %s / %s", meta.Format, meta.KDF)
		}
		salt, err := base64.RawStdEncoding.DecodeString(meta.Salt)
		if err != nil || len(salt) == 0 {
			return nil, nil, fmt.Errorf("加密盐数据损坏")
		}
		nonce, err := base64.RawStdEncoding.DecodeString(meta.Nonce)
		if err != nil || len(nonce) == 0 {
			return nil, nil, fmt.Errorf("加密随机数损坏")
		}
		ciphertext, err := readZipEntryBytes(zr.File, archiveEncPayloadData)
		if err != nil {
			return nil, nil, fmt.Errorf("读取加密载荷失败: %w", err)
		}

		key, err := deriveArchiveKey(password, salt)
		if err != nil {
			return nil, nil, err
		}
		defer zeroBytes(key)

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, nil, err
		}
		if len(nonce) != gcm.NonceSize() {
			return nil, nil, fmt.Errorf("加密随机数长度异常")
		}

		aad := []byte(archiveFormat + ":v1")
		payloadBytes, err = gcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return nil, nil, fmt.Errorf("迁移包密码错误或文件已损坏")
		}
	}

	innerReader, err := zip.NewReader(bytes.NewReader(payloadBytes), int64(len(payloadBytes)))
	if err != nil {
		return nil, nil, fmt.Errorf("解析内层迁移包失败: %w", err)
	}
	return &manifest, innerReader, nil
}

// readZipEntryBytes 从 ZIP 条目列表中按规范化的正斜杠路径读取完整字节内容。
func readZipEntryBytes(files []*zip.File, targetName string) ([]byte, error) {
	for _, f := range files {
		if filepath.ToSlash(strings.TrimSpace(f.Name)) != targetName {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("缺少文件 %s", targetName)
}
