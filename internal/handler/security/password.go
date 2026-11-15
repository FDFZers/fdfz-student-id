package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	notifysvc "fdfz-student-id/internal/service/notify"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"

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

	notifysvc.ToUser(c.Request.Context(), claims.UserID, notifysvc.NewMessage(
		"密码已修改",
		"你的账号密码已修改",
		"你好！你的复旦附中学生 ID 账号密码已于北京时间 "+notifysvc.BeijingTime()+" 修改。",
		"如非本人操作，请立即重置密码并联系管理员。",
	))

	handling.RespondOK(c)
	return nil
}
