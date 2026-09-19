package fileutils

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fdfz-student-id/internal/storage"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

var ErrSHA512Mismatch = errors.New("sha512 mismatch")

type TempWriter struct {
	tmpFile   *os.File
	tmpPath   string
	dstPath   string
	dir       string
	committed bool
	closed    bool

	hasher       hash.Hash
	expectedHash *string
	actualHash   string
}

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

func (w *TempWriter) SHA512Sum() string {
	return hex.EncodeToString(w.hasher.Sum(nil))
}

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

func (w *TempWriter) WriteFrom(r io.Reader) (int64, error) {
	if w.closed {
		return 0, errors.New("writer already closed")
	}
	buf := make([]byte, 32*1024)
	mw := io.MultiWriter(w.tmpFile, w.hasher)
	return io.CopyBuffer(mw, r, buf)
}

func (w *TempWriter) Commit() error {
	if w.committed {
		return errors.New("already committed")
	}
	if w.closed {
		return errors.New("writer already closed")
	}

	w.actualHash = w.SHA512Sum()

	if w.expectedHash != nil && *w.expectedHash != w.actualHash {
		if err := w.tmpFile.Close(); err != nil {
			slog.Warn("Failed to close temp file", "error", err)
		}
		w.closed = true
		if err := os.Remove(w.tmpPath); err != nil {
			slog.Warn("Failed to remove temp file", "error", err)
		}
		return fmt.Errorf("%w: expected %s, got %s", ErrSHA512Mismatch, w.expectedHash, w.actualHash)
	}

	if err := w.tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := w.tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	w.closed = true

	if err := MoveFile(w.tmpPath, w.dstPath); err != nil {
		return fmt.Errorf("move temp file: %w", err)
	}

	w.committed = true
	return nil
}

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
