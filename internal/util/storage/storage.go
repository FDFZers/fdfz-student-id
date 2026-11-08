// Package storage 管理本地存储目录与上传临时路径的生成。
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

// StorageDir 是服务本地临时目录根，默认 ./storage。
var StorageDir = "./storage"

// TempDir 是临时文件目录，供 TempWriter 创建临时文件。
var TempDir = filepath.Join(StorageDir, "tmp")

// AppSharedDir 是应用共享目录 <SHARED_DIR>/student_id，由 EnsureDir 初始化。
var AppSharedDir string

// EnsureDir 创建临时目录与共享目录下的 uploads 子目录，并记录 AppSharedDir。
// 注意：必须在启动阶段调用一次，TempWriter 与 UploadTempPath 依赖这两个目录已存在。
func EnsureDir() error {
	AppSharedDir = filepath.Join(cfg.C.SharedDir, "student_id")
	if err := os.MkdirAll(TempDir, 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(AppSharedDir, "uploads"), 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	return nil
}

// UploadTempPath 生成一个当前不存在的随机上传路径，最多重试 100 次。
// 返回相对 SHARED_DIR 的路径（上报给 filestore）与本地文件系统路径（用于写文件）。
// 注意：只生成路径不创建文件，调用方需自行创建；并发调用间不做加锁，依赖随机名避免冲突。
func UploadTempPath() (string, string, error) {
	for range 100 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", "", err
		}

		rel := path.Join("uploads", hex.EncodeToString(b[:]))
		p := filepath.Join(AppSharedDir, filepath.FromSlash(rel))

		_, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			return path.Join("student_id", rel), p, nil
		}
		if err != nil {
			return "", "", err
		}
	}
	return "", "", errors.New("storage: generate upload temp path")
}
