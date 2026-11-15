package security

import (
	"fdfz-student-id/internal/errs"
	authsvc "fdfz-student-id/internal/service/auth"
	notifysvc "fdfz-student-id/internal/service/notify"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// deleteAccountHandler 注销当前账号：撤销全部会话与提权令牌，写入 7 天冷静期后清理 Cookie。
// 注意：冷静期内重新登录会取消注销，到期后由定时任务完成软删除。
func deleteAccountHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	// 立即撤销全部登录会话与提权令牌，避免冷静期内会话继续可用
	if err := authsvc.RevokeAllUserSessions(c.Request.Context(), claims.UserID); err != nil {
		return err
	}
	if err := authsvc.RevokeUserStepups(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	// 写入冷静期截止时间，重复调用不会延长已排定的时间
	scheduledAt, err := usersvc.ScheduleAccountDeletion(c.Request.Context(), claims.UserID, usersvc.AccountDeletionDelay)
	if err != nil {
		return err
	}

	notifysvc.ToUser(c.Request.Context(), claims.UserID, notifysvc.NewMessage(
		"账号注销申请已提交",
		"你的账号将在 7 天后注销",
		"你好！你的复旦附中学生 ID 账号已于 "+notifysvc.BeijingTime()+"（北京时间）提交注销申请，将在 7 天冷静期后删除。",
		"冷静期内重新登录可取消注销。如非本人操作，请立即联系管理员。",
	))

	// 清理当前请求的登录 Cookie，返回排定的注销时间
	handling.ClearSessionCookies(c)

	slog.Info("Account deletion scheduled", "user_id", claims.UserID, "scheduled_at", scheduledAt)

	c.JSON(http.StatusOK, gin.H{
		"scheduled_at": scheduledAt,
	})
	return nil
}

// deleteUserHandler 管理员删除指定用户：撤销其会话与提权令牌后立即软删除。
// 需要 users.delete 权限；不能删除自己或拥有写权限的账号，软删除后记录保留供外键引用。
func deleteUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	// 校验目标用户 ID
	targetID, err := handling.ParseID(c, "id", "用户")
	if err != nil {
		return err
	}
	if targetID == claims.UserID {
		return errs.BadRequestError().AppendDetails("不能删除自己")
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	hasWritePermission, err := handling.UserHasWritePerm(c.Request.Context(), targetID)
	if err != nil {
		return err
	}
	if hasWritePermission {
		return errs.PermissionDeniedError().AppendDetails("不能删除拥有写权限的用户")
	}

	// 撤销目标用户会话与提权令牌，防止删除后令牌继续生效
	if err := authsvc.RevokeAllUserSessions(c.Request.Context(), targetID); err != nil {
		return err
	}
	if err := authsvc.RevokeUserStepups(c.Request.Context(), targetID); err != nil {
		return err
	}

	// 软删除用户并清理关联数据（密码、TOTP、用户组、权限授予等）
	if err := usersvc.DeleteUser(c.Request.Context(), targetID); err != nil {
		return err
	}

	slog.Info("User deleted", "user_id", targetID, "operator_id", claims.UserID)

	handling.RespondOK(c)
	return nil
}
