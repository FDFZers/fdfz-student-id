package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// changePasswordReq 修改密码请求体；新密码需满足密码复杂度校验。
type changePasswordReq struct {
	OldPassword         string `json:"old_password"`
	NewPassword         string `json:"new_password"`
	RevokeOtherSessions *bool  `json:"revoke_other_sessions"` // 是否撤销其他会话，为空时按 true 处理
}

// changePasswordHandler 修改当前账号密码：重新校验原密码后写入新哈希，并使全部提权令牌失效。
// 注意：默认同时撤销除当前会话外的其他登录会话。
func changePasswordHandler(c *gin.Context) *errs.Error {
	var req changePasswordReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 提权令牌携带当前登录会话 UUID，用于改密后保留本会话
	currentSessionID, e := uuid.Parse(claims.SessionID.String)
	if e != nil {
		return errs.InvalidTokenError().AppendDetails("会话 ID 格式错误")
	}

	// 封禁用户不允许改密
	ban, err := usersvc.GetUserBan(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 校验新密码复杂度，并拒绝与原密码相同的新密码
	if err := handling.ValidatePassword(req.NewPassword); err != nil {
		return err
	}
	if req.NewPassword == req.OldPassword {
		return errs.BadRequestError().AppendDetails("新密码不能与原密码相同")
	}

	current, err := usersvc.GetUserPassword(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if current == nil {
		return errs.NotFoundError().AppendDetails("密码不存在")
	}
	if ok, e := crypto.VerifyArgon2ID(req.OldPassword, current.Password); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify old password")
	} else if !ok {
		return errs.ForbiddenError().AppendDetails("原密码错误")
	}

	// 哈希并写入新密码
	pwdHash, e := crypto.HashArgon2ID(req.NewPassword)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to hash new password").AppendDetails("密码哈希失败")
	}

	if err := usersvc.UpsertUserPassword(c.Request.Context(), &model.UserPassword{
		UserID:   claims.UserID,
		Password: pwdHash,
	}); err != nil {
		return err
	}

	// 用户自行改密后不再需要重设提示
	if err := usersvc.SetPasswordResetRequired(c.Request.Context(), claims.UserID, false); err != nil {
		return err
	}

	// 使全部提权令牌失效，并按需撤销其他会话
	if err := authsvc.RevokeUserStepups(c.Request.Context(), claims.UserID); err != nil {
		return err
	}
	handling.ClearStepupCookie(c)

	if req.RevokeOtherSessions == nil || *req.RevokeOtherSessions {
		if err := authsvc.RevokeOtherUserSessions(c.Request.Context(), claims.UserID, currentSessionID); err != nil {
			return err
		}
	}

	notificationsvc.ToUser(c.Request.Context(), claims.UserID, notificationsvc.NewPasswordChangedMessage())

	handling.RespondOK(c)
	return nil
}

// adminResetPasswordReq 是管理员重置他人密码的请求体。
type adminResetPasswordReq struct {
	NewPassword string `json:"new_password"`

	// RequirePasswordReset 是否要求目标用户下次登录后重设密码，缺省为 true。
	RequirePasswordReset *bool `json:"require_password_reset"`
}

// resetUserPasswordHandler 管理员重置指定用户的密码，并撤销其全部会话与提权令牌。
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

	notificationsvc.ToUser(c.Request.Context(), targetID, notificationsvc.NewAdminPasswordResetMessage(requireReset))

	slog.Info("User password reset by admin",
		"user_id", targetID,
		"operator_id", claims.UserID,
		"require_password_reset", requireReset,
	)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
