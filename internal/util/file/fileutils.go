package fileutils

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func(in *os.File) {
		err := in.Close()
		if err != nil {
			slog.Warn("Failed to close file", "error", err)
		}
	}(in)

	out, err := os.CreateTemp(filepath.Dir(dst), ".dst-*")
	if err != nil {
		return err
	}
	tmpOut := out.Name()

	if _, err := io.Copy(out, in); err != nil {
		err := out.Close()
		if err != nil {
			slog.Warn("Failed to close temp file", "error", err)
		}
		err = os.Remove(tmpOut)
		if err != nil {
			slog.Warn("Failed to remove temp file", "error", err)
		}
		return err
	}
	if err := out.Sync(); err != nil {
		err := out.Close()
		if err != nil {
			slog.Warn("Failed to close temp file", "error", err)
		}
		err = os.Remove(tmpOut)
		if err != nil {
			slog.Warn("Failed to remove temp file", "error", err)
		}
		return err
	}
	if err := out.Close(); err != nil {
		err := os.Remove(tmpOut)
		if err != nil {
			slog.Warn("Failed to remove temp file", "error", err)
		}
		return err
	}
	return os.Rename(tmpOut, dst)
}

func MoveFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		if err := CopyFile(src, dst); err != nil {
			return fmt.Errorf("copy to dst: %w", err)
		}
		if err := os.Remove(src); err != nil {
			slog.Warn("Failed to remove temp file", "error", err)
		}
	}
	return nil
}
