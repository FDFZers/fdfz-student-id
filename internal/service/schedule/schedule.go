package schedule

import (
	"context"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"log/slog"

	"github.com/robfig/cron/v3"
)

func ScheduleCron() (*cron.Cron, error) {
	c := cron.New()

	_, err := c.AddFunc("0 2 * * *", func() {
		_, err := auth.DeleteStaleSessions(context.Background())
		if err != nil {
			slog.Error("Failed to delete stale sessions", "error", err.Info)
		}
	})
	if err != nil {
		return nil, err
	}

	_, err = c.AddFunc("0 */4 * * *", func() {
		_, err := user.CleanupExpiredBans(context.Background())
		if err != nil {
			slog.Error("Failed to cleanup expired bans", "error", err.Info)
		}
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}
