package schedule

import (
	"context"
	"fdfz-student-id/internal/service/auth"

	"github.com/robfig/cron/v3"
)

func ScheduleCron() (*cron.Cron, error) {
	c := cron.New()

	_, err := c.AddFunc("0 2 * * *", func() {
		auth.DeleteStaleSessions(context.Background())
	})
	if err != nil {
		return nil, err
	}

	return c, nil
}
