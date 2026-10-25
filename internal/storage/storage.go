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

var StorageDir = "./storage"
var TempDir = filepath.Join(StorageDir, "tmp")
var AppSharedDir string

// sharedAppDirName 是本服务在共享目录下的子目录名，也是回报给 filestore 的
// file_path 的第一段。它属于跨服务契约，恒用 '/' 拼接，不参与本地路径计算。
const sharedAppDirName = "student_id"

func EnsureDir() error {
	AppSharedDir = filepath.Join(cfg.C.SharedDir, sharedAppDirName)
	if err := os.MkdirAll(TempDir, 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(AppSharedDir, "uploads"), 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	return nil
}

// UploadTempPath 返回两个路径，语义必须分开：
//   - 第一个是回报给 filestore 的相对路径，URL 风格、恒用 '/'，与本地平台无关；
//   - 第二个是本地文件系统路径，必须用 filepath 计算（Windows 下分隔符为 '\'）。
//
// 两者混用会把绝对路径当成相对路径发出去，被 filestore 的 SafeJoin 拒绝（Windows 必现）。
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
			return path.Join(sharedAppDirName, rel), p, nil
		}
		if err != nil {
			return "", "", err
		}
	}
	return "", "", errors.New("storage: generate upload temp path")
}
