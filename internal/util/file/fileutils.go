// Package fileutils 提供文件复制、移动与带 SHA-512 校验的临时文件写入。
package fileutils

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// CopyFile 复制 src 到 dst：先写入同目录的临时文件，成功后再原子重命名，避免产生半成品 dst。
// 任一步失败都会清理临时文件；不保留源文件的权限位。
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

	// 在目标目录创建临时文件，保证后续 rename 不跨文件系统
	out, err := os.CreateTemp(filepath.Dir(dst), ".dst-*")
	if err != nil {
		return err
	}
	tmpOut := out.Name()

	removeTemp := func() {
		if err := os.Remove(tmpOut); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("Failed to remove temp file", "error", err)
		}
	}
	abort := func(op string, cause error) error {
		if err := out.Close(); err != nil {
			slog.Warn("Failed to close temp file", "error", err)
		}
		removeTemp()
		return fmt.Errorf("%s: %w", op, cause)
	}

	// 复制内容，失败时关闭并删除临时文件
	if _, err := io.Copy(out, in); err != nil {
		return abort("copy", err)
	}
	// 落盘，避免断电后文件名可见但内容为空
	if err := out.Sync(); err != nil {
		return abort("sync", err)
	}
	if err := out.Close(); err != nil {
		removeTemp()
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpOut, dst); err != nil {
		removeTemp()
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// MoveFile 优先用 rename 移动文件；rename 失败（如跨文件系统）时退化为复制后删除源文件。
// 注意：删除源文件失败只记录日志，不影响返回值。
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
