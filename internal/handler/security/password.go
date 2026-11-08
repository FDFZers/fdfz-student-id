package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
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
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)

	// 提权令牌携带当前登录会话 UUID，用于改密后保留本会话
	currentSessionID, e := uuid.Parse(claims.SessionID.String)
	if e != nil {
		return errs.InvalidTokenError().AppendDetails("会话 ID 格式错误")
	}

	// 封禁用户不允许改密
	ban, err := user.GetUserBan(c.Request.Context(), claims.UserID)
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

	// 校验原密码；service 查询不存在的密码记录返回 (nil, nil)，由 handler 决定 404。
	current, err := user.GetUserPassword(c.Request.Context(), claims.UserID)
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

	if err := user.UpsertUserPassword(c.Request.Context(), &model.UserPassword{
		UserID:   claims.UserID,
		Password: pwdHash,
	}); err != nil {
		return err
	}

	// 使全部提权令牌失效，并按需撤销其他会话
	if err := auth.RevokeUserStepups(c.Request.Context(), claims.UserID); err != nil {
		return err
	}
	handling.ClearStepupCookie(c)

	if req.RevokeOtherSessions == nil || *req.RevokeOtherSessions {
		if err := auth.RevokeOtherUserSessions(c.Request.Context(), claims.UserID, currentSessionID); err != nil {
			return err
		}
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
