package security

import (
	"fdfz-student-id/internal/errs"
	authsvc "fdfz-student-id/internal/service/auth"
	notifysvc "fdfz-student-id/internal/service/notify"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// adminResetPasswordReq 是管理员重置他人密码的请求体。
type adminResetPasswordReq struct {
	NewPassword string `json:"new_password"` // 管理员设置的新密码

	// RequirePasswordReset 是否要求目标用户下次登录后重设密码，缺省为 true。
	RequirePasswordReset *bool `json:"require_password_reset"`
}

// resetUserPasswordHandler 管理员重置指定用户的密码：校验后写入新密码哈希、撤销其全部会话与提权令牌。
// 需要 users.password.write 权限；默认给目标账号打上「需要重设密码」标记，用户登录后会收到提示。
// 注意：不能重置自己或拥有管理侧写权限的账号，避免绕过原密码与二次验证接管高权限账号。
func resetUserPasswordHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	targetID, err := handling.ParseID(c, "id", "用户")
	if err != nil {
		return err
	}
	if targetID == claims.UserID {
		return errs.BadRequestError().AppendDetails("不能重置自己的密码，请使用修改密码接口")
	}

	var req adminResetPasswordReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	hasWritePermission, err := handling.UserHasWritePerm(c.Request.Context(), targetID)
	if err != nil {
		return err
	}
	if hasWritePermission {
		return errs.PermissionDeniedError().AppendDetails("不能重置拥有写权限的用户的密码")
	}

	// 拒绝把密码设置为原密码，避免管理员误操作后仍提示用户重设。
	current, err := usersvc.GetUserPassword(c.Request.Context(), targetID)
	if err != nil {
		return err
	}
	if current != nil {
		if ok, e := crypto.VerifyArgon2ID(req.NewPassword, current.Password); e != nil {
			return errs.CreateAndLogInternalError(e, "Failed to verify target user password").AppendDetails("原密码校验失败")
		} else if ok {
			return errs.BadRequestError().AppendDetails("新密码不能与原密码相同")
		}
	}

	pwdHash, e := crypto.HashArgon2ID(req.NewPassword)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to hash new password").AppendDetails("密码哈希失败")
	}

	// 先撤销会话再改密：撤销失败时密码保持不变，避免出现改密后旧会话仍可用的窗口。
	if err := authsvc.RevokeAllUserSessions(c.Request.Context(), targetID); err != nil {
		return err
	}
	if err := authsvc.RevokeUserStepups(c.Request.Context(), targetID); err != nil {
		return err
	}

	requireReset := req.RequirePasswordReset == nil || *req.RequirePasswordReset
	if err := usersvc.AdminResetUserPassword(c.Request.Context(), targetID, pwdHash, requireReset); err != nil {
		// 服务层错误已带「密码重置失败」上下文，直接封口避免 Wrap 重复追加。
		return err.Seal()
	}

	// 通知目标用户密码已被管理员重置
	footer := "如非本人操作，请立即联系管理员。"
	if requireReset {
		footer = "请使用新密码登录，并按提示重设密码。如非本人操作，请立即联系管理员。"
	}
	notifysvc.ToUser(c.Request.Context(), targetID, notifysvc.NewMessage(
		"密码已被管理员重置",
		"你的账号密码已被管理员重置",
		"你好！你的复旦附中学生 ID 账号密码已于北京时间 "+notifysvc.BeijingTime()+" 被管理员重置。",
		footer,
	))

	slog.Info("User password reset by admin",
		"user_id", targetID,
		"operator_id", claims.UserID,
		"require_password_reset", requireReset,
	)

	c.JSON(http.StatusOK, gin.H{
		"password_reset_required": requireReset,
	})
	return nil
}
