package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

func deleteAccountHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	if err := auth.RevokeAllUserSessions(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	scheduledAt, err := user.ScheduleAccountDeletion(c.Request.Context(), claims.UserID, user.AccountDeletionDelay)
	if err != nil {
		return err
	}

	handling.ClearSessionCookies(c)

	c.JSON(http.StatusOK, gin.H{
		"scheduled_at": scheduledAt,
	})
	return nil
}
