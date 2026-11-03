package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func deleteAccountHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	if err := auth.RevokeAllUserSessions(c.Request.Context(), claims.UserID); err != nil {
		return err
	}
	if err := auth.RevokeUserStepups(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	scheduledAt, err := user.ScheduleAccountDeletion(c.Request.Context(), claims.UserID, user.AccountDeletionDelay)
	if err != nil {
		return err
	}

	handling.ClearSessionCookies(c)

	slog.Info("Account deletion scheduled", "user_id", claims.UserID, "scheduled_at", scheduledAt)

	c.JSON(http.StatusOK, gin.H{
		"scheduled_at": scheduledAt,
	})
	return nil
}

func deleteUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	targetID, e := strconv.ParseInt(c.Param("id"), 10, 64)
	if e != nil || targetID <= 0 {
		return errs.BadRequestError().AppendDetails("无效的用户 ID")
	}
	if targetID == claims.UserID {
		return errs.BadRequestError().AppendDetails("不能删除自己")
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	if err := auth.RevokeAllUserSessions(c.Request.Context(), targetID); err != nil {
		return err
	}
	if err := auth.RevokeUserStepups(c.Request.Context(), targetID); err != nil {
		return err
	}

	if err := user.DeleteUser(c.Request.Context(), targetID); err != nil {
		return err
	}

	slog.Info("User deleted", "user_id", targetID, "operator_id", claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
