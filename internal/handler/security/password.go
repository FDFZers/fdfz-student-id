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

type changePasswordReq struct {
	OldPassword         string `json:"old_password"`
	NewPassword         string `json:"new_password"`
	RevokeOtherSessions *bool  `json:"revoke_other_sessions"`
}

func changePasswordHandler(c *gin.Context) *errs.Error {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)

	currentSessionID, e := uuid.Parse(claims.SessionID.String)
	if e != nil {
		return errs.InvalidTokenError().AppendDetails("无效的会话", "鉴权失败")
	}

	ban, err := user.GetUserBan(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	if err := handling.ValidatePassword(req.NewPassword); err != nil {
		return err
	}
	if req.NewPassword == req.OldPassword {
		return errs.BadRequestError().AppendDetails("新密码不能与原密码相同")
	}

	current, err := user.GetUserPassword(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if ok, e := crypto.VerifyArgon2ID(req.OldPassword, current.Password); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify old password")
	} else if !ok {
		return errs.ForbiddenError().AppendDetails("原密码错误")
	}

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
