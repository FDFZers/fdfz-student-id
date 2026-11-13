package schedule

import (
	"context"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"log/slog"

	"github.com/robfig/cron/v3"
)

// ScheduleCron 创建 cron 实例并注册全部定时任务；调用方负责启动与停止。
// 注意：任务内使用 context.Background()，不随单个请求取消；清理失败只记录日志。
func ScheduleCron() (*cron.Cron, error) {
	c := cron.New()

	// 每天 02:00 清理过期的鉴权会话
	_, err := c.AddFunc("0 2 * * *", func() {
		_, err := auth.DeleteStaleSessions(context.Background())
		if err != nil {
			slog.Error("Failed to delete stale sessions", "error", err.Info)
		}
	})
	if err != nil {
		return nil, err
	}

	// 每 10 分钟清理已到期的用户封禁
	_, err = c.AddFunc("*/10 * * * *", func() {
		_, err := user.CleanupExpiredBans(context.Background())
		if err != nil {
			slog.Error("Failed to cleanup expired bans", "error", err.Info)
		}
	})
	if err != nil {
		return nil, err
	}

	// 每 10 分钟完成已到冷静期的账号注销
	_, err = c.AddFunc("*/10 * * * *", func() {
		count, err := user.FinalizeDueAccountDeletions(context.Background())
		if err != nil {
			slog.Error("Failed to finalize scheduled account deletions", "error", err.Info)
		} else if count > 0 {
			slog.Info("Finalized scheduled account deletions", "count", count)
		}
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}
