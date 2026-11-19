// chromium_storage.go 负责离线打包与原子恢复 Chromium 非 DPAPI 加密的 Web 存储目录
// （Local Storage/leveldb、Session Storage 与可选 IndexedDB），以及提供原子写/原子替换和备份基础工具。
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// storageCategory 描述一类可独立迁移的浏览器 Web Storage 目录。
type storageCategory struct {
	Key    string // 归档内逻辑标识
	RelDir string // 相对于 user_data_dir 的路径
}

var (
	storageCatLocalStorage = storageCategory{
		Key:    "local-storage",
		RelDir: "Default/Local Storage/leveldb",
	}
	storageCatSessionStorage = storageCategory{
		Key:    "session-storage",
		RelDir: "Default/Session Storage",
	}
	storageCatIndexedDB = storageCategory{
		Key:    "indexeddb",
		RelDir: "Default/IndexedDB",
	}
)

// allStorageCategories 返回工具支持的全部 Web Storage 迁移类别列表。
func allStorageCategories() []storageCategory {
	return []storageCategory{
		storageCatLocalStorage,
		storageCatSessionStorage,
		storageCatIndexedDB,
	}
}

// isTransientLevelDBFile 过滤 LevelDB 运行期锁文件与诊断日志（LOCK / LOG / LOG.old），
// 避免跨机带入脏锁导致目标 Chromium 启动阻塞。
func isTransientLevelDBFile(fileName string) bool {
	upper := strings.ToUpper(strings.TrimSpace(fileName))
	return upper == "LOCK" || upper == "LOG" || upper == "LOG.OLD"
}

// writeProfileStorageCategoryToZip 将单个 Web Storage 目录打包到内层 ZIP（跳过 LOCK/LOG 等临时文件）。
func writeProfileStorageCategoryToZip(zw *zip.Writer, userDataDir string, profileID string, cat storageCategory) (fileCount int, err error) {
	srcDir := filepath.Join(userDataDir, filepath.FromSlash(cat.RelDir))
	if !dirExists(srcDir) {
		return 0, nil
	}

	prefix := fmt.Sprintf("profiles/%s/storage/%s", profileID, cat.Key)
	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == "." {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if isTransientLevelDBFile(d.Name()) {
			return nil
		}

		zipEntryName := prefix + "/" + relSlash
		w, err := zw.Create(zipEntryName)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		fileCount++
		return nil
	})
	return fileCount, err
}

// restoreProfileStorageCategory 从内层 ZIP 原子恢复某类 Web Storage 目录（含可选备份和失败回滚）。
func restoreProfileStorageCategory(files []*zip.File, targetUserDataDir string, cat storageCategory, backupDir string) (restoredFiles int, err error) {
	if len(files) == 0 {
		return 0, nil
	}

	targetDir := filepath.Join(targetUserDataDir, filepath.FromSlash(cat.RelDir))
	parentDir := filepath.Dir(targetDir)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return 0, fmt.Errorf("创建目标存储父目录失败: %w", err)
	}

	stagingDir, err := os.MkdirTemp(parentDir, ".migrator-stage-*")
	if err != nil {
		return 0, fmt.Errorf("创建临时存储解压目录失败: %w", err)
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	expectedPrefix := "/storage/" + cat.Key + "/"
	for _, zf := range files {
		name := filepath.ToSlash(zf.Name)
		idx := strings.Index(name, expectedPrefix)
		if idx < 0 {
			continue
		}
		rel := name[idx+len(expectedPrefix):]
		if rel == "" || strings.HasSuffix(rel, "/") {
			continue
		}
		cleanRel := filepath.Clean(filepath.FromSlash(rel))
		if cleanRel == "." || strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			return 0, fmt.Errorf("归档内存在非法存储路径: %s", rel)
		}
		if isTransientLevelDBFile(filepath.Base(cleanRel)) {
			continue
		}

		dstPath := filepath.Join(stagingDir, cleanRel)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return 0, err
		}
		rc, err := zf.Open()
		if err != nil {
			return 0, err
		}
		out, err := os.Create(dstPath)
		if err != nil {
			rc.Close()
			return 0, err
		}
		_, copyErr := io.Copy(out, rc)
		closeOutErr := out.Close()
		closeInErr := rc.Close()
		if copyErr != nil {
			return 0, copyErr
		}
		if closeOutErr != nil {
			return 0, closeOutErr
		}
		if closeInErr != nil {
			return 0, closeInErr
		}
		restoredFiles++
	}

	if restoredFiles == 0 {
		return 0, nil
	}

	if backupDir != "" && dirExists(targetDir) {
		backupTarget := filepath.Join(backupDir, filepath.FromSlash(cat.RelDir))
		if err := copyDir(targetDir, backupTarget); err != nil {
			return 0, fmt.Errorf("备份原 %s 失败: %w", cat.RelDir, err)
		}
	}

	oldSwapDir := ""
	if dirExists(targetDir) {
		oldSwapDir = targetDir + fmt.Sprintf(".migrator-old-%d", os.Getpid())
		_ = os.RemoveAll(oldSwapDir)
		if err := os.Rename(targetDir, oldSwapDir); err != nil {
			return 0, fmt.Errorf("移走原存储目录 %s 失败（请确认浏览器已完全关闭）: %w", cat.RelDir, err)
		}
	}

	if err := os.Rename(stagingDir, targetDir); err != nil {
		if oldSwapDir != "" {
			_ = os.Rename(oldSwapDir, targetDir)
		}
		return 0, fmt.Errorf("提交新存储目录 %s 失败: %w", cat.RelDir, err)
	}
	cleanupStage = false
	if oldSwapDir != "" {
		_ = os.RemoveAll(oldSwapDir)
	}
	return restoredFiles, nil
}

// copyFile 复制单个文件（目标权限收紧为 0600，自动创建父目录）。
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyDir 递归复制目录用于回滚备份，自动忽略符号链接与 LevelDB 临时锁文件。
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := dst
		if rel != "." {
			target = filepath.Join(dst, rel)
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if isTransientLevelDBFile(d.Name()) {
			return nil
		}
		return copyFile(path, target)
	})
}

// atomicWriteFile 先写入同目录临时文件再原子替换目标文件，防止半写入损坏 Local State 或配置文件。
func atomicWriteFile(targetPath string, content []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	tmpPath := targetPath + fmt.Sprintf(".migrator.%d.tmp", os.Getpid())
	_ = os.Remove(tmpPath)
	if err := os.WriteFile(tmpPath, content, perm); err != nil {
		return err
	}
	if err := atomicReplaceFile(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// atomicReplaceFile 通过“移走旧文件 -> 移入新文件 -> 删除旧文件”三步实现跨平台（含 Windows）安全替换与失败回滚。
func atomicReplaceFile(tmpPath, targetPath string) error {
	oldPath := ""
	if fileExists(targetPath) {
		oldPath = targetPath + fmt.Sprintf(".migrator-old-%d", os.Getpid())
		_ = os.Remove(oldPath)
		if err := os.Rename(targetPath, oldPath); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		if oldPath != "" {
			_ = os.Rename(oldPath, targetPath)
		}
		return err
	}
	if oldPath != "" {
		_ = os.Remove(oldPath)
	}
	return nil
}
