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

func EnsureDir() error {
	AppSharedDir = filepath.Join(cfg.C.SharedDir, "student_id")
	if err := os.MkdirAll(TempDir, 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	if err := os.MkdirAll(path.Join(AppSharedDir, "uploads"), 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	return nil
}

func UploadTempPath() (string, string, error) {
	for range 100 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", "", err
		}

		rel := path.Join("uploads", hex.EncodeToString(b[:]))
		p := path.Join(AppSharedDir, rel)

		_, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			return path.Join(path.Base(AppSharedDir), rel), p, nil
		}
		if err != nil {
			return "", "", err
		}
	}
	return "", "", errors.New("storage: generate upload temp path")
}
