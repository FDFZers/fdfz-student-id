package fileutils

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fdfz-student-id/internal/util/storage"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// ErrSHA512Mismatch 表示写入内容与期望的 SHA-512 不一致。
var ErrSHA512Mismatch = errors.New("sha512 mismatch")

// TempWriter 把数据流式写入临时文件并同步计算 SHA-512，Commit 时校验后移动到目标路径。
type TempWriter struct {
	tmpFile   *os.File
	tmpPath   string // 临时文件路径（位于 storage.TempDir）
	dstPath   string // 提交后移动到的目标路径
	dir       string // 目标文件所在目录，创建时确保存在
	committed bool   // 是否已成功提交
	closed    bool   // 是否已关闭，关闭后不可再写入

	hasher       hash.Hash // SHA-512 计算器
	expectedHash *string   // 期望的 SHA-512，nil 表示不做校验
	actualHash   string    // 实际计算的 SHA-512，Commit 时写入
}

// NewTempWriter 创建向 dstPath 写入的临时文件写入器；expectedHash 非 nil 时 Commit 会校验 SHA-512。
// 注意：临时文件位于 storage.TempDir，与目标目录可能不在同一文件系统。
func NewTempWriter(dstPath string, sha512Sum *string) (*TempWriter, error) {
	if dstPath == "" {
		return nil, errors.New("dstPath is empty")
	}

	dir := filepath.Dir(dstPath)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	f, err := os.CreateTemp(storage.TempDir, "tempwriter-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	return &TempWriter{
		tmpFile:      f,
		tmpPath:      f.Name(),
		dstPath:      dstPath,
		dir:          dir,
		hasher:       sha512.New(),
		expectedHash: sha512Sum,
	}, nil
}

func (w *TempWriter) removeTemp() {
	if err := os.Remove(w.tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("Failed to remove temp file", "error", err)
	}
}

// SHA512Sum 返回已写入内容的 SHA-512 十六进制串。
func (w *TempWriter) SHA512Sum() string {
	return hex.EncodeToString(w.hasher.Sum(nil))
}

// Write 写入数据并同步更新 SHA-512（实现 io.Writer）。
func (w *TempWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("writer already closed")
	}
	n, err := w.tmpFile.Write(p)
	if n > 0 {
		if _, err = w.hasher.Write(p[:n]); err != nil {
			slog.Warn("Failed to write to hasher", "error", err)
		}
	}
	return n, err
}

// WriteFrom 从 r 流式读取并写入临时文件，返回写入字节数。
func (w *TempWriter) WriteFrom(r io.Reader) (int64, error) {
	if w.closed {
		return 0, errors.New("writer already closed")
	}
	buf := make([]byte, 32*1024)
	mw := io.MultiWriter(w.tmpFile, w.hasher)
	return io.CopyBuffer(mw, r, buf)
}

// Commit 校验 SHA-512、落盘并关闭临时文件，最后移动到目标路径。
// 注意：SHA-512 不匹配或后续步骤失败时文件不会提交，临时文件会被清理。
func (w *TempWriter) Commit() error {
	if w.committed {
		return errors.New("already committed")
	}
	if w.closed {
		return errors.New("writer already closed")
	}

	// 校验 SHA-512
	w.actualHash = w.SHA512Sum()

	if w.expectedHash != nil && *w.expectedHash != w.actualHash {
		if err := w.tmpFile.Close(); err != nil {
			slog.Warn("Failed to close temp file", "error", err)
		}
		w.closed = true
		w.removeTemp()
		return fmt.Errorf("%w: expected %s, got %s", ErrSHA512Mismatch, *w.expectedHash, w.actualHash)
	}

	if err := w.tmpFile.Sync(); err != nil {
		if e := w.tmpFile.Close(); e != nil {
			slog.Warn("Failed to close temp file", "error", e)
		}
		w.closed = true
		w.removeTemp()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := w.tmpFile.Close(); err != nil {
		w.closed = true
		w.removeTemp()
		return fmt.Errorf("close temp file: %w", err)
	}
	w.closed = true

	if err := MoveFile(w.tmpPath, w.dstPath); err != nil {
		w.removeTemp()
		return fmt.Errorf("move temp file: %w", err)
	}

	w.committed = true
	return nil
}

// Abort 放弃写入：关闭并删除临时文件；已提交时为空操作。
func (w *TempWriter) Abort() {
	if w.committed {
		return
	}
	if !w.closed {
		if err := w.tmpFile.Close(); err != nil {
			slog.Warn("Failed to close temp file", "error", err)
		}
		w.closed = true
	}
	if err := os.Remove(w.tmpPath); err != nil {
		slog.Warn("Failed to remove temp file", "error", err)
	}
}
