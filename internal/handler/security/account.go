package security

import (
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

func deleteAccountHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	if err := auth.RevokeAllUserSessions(c.Request.Context(), claims.UserID); err != nil {
		err.AppendDetails("账号注销失败").Respond(c)
		return
	}

	scheduledAt, err := user.ScheduleAccountDeletion(c.Request.Context(), claims.UserID, user.AccountDeletionDelay)
	if err != nil {
		err.AppendDetails("账号注销失败").Respond(c)
		return
	}

	handling.ClearSessionCookies(c)

	c.JSON(http.StatusOK, gin.H{
		"scheduled_at": scheduledAt,
	})
}
