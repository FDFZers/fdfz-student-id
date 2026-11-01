package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func changePasswordHandler(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "修改密码失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	ban, err := user.GetUserBan(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("修改密码失败").Respond(c)
		return
	}
	if ban != nil {
		handling.RespondBanned(c, ban, "修改密码失败")
		return
	}

	if err := handling.ValidatePassword(req.NewPassword); err != nil {
		err.AppendDetails("修改密码失败").Respond(c)
		return
	}
	if req.NewPassword == req.OldPassword {
		errs.BadRequestError().AppendDetails("新密码不能与原密码相同", "修改密码失败").Respond(c)
		return
	}

	current, err := user.GetUserPassword(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("修改密码失败").Respond(c)
		return
	}
	if ok, e := crypto.VerifyArgon2ID(req.OldPassword, current.Password); e != nil {
		errs.CreateAndLogInternalError(e, "Failed to verify old password").AppendDetails("修改密码失败").Respond(c)
		return
	} else if !ok {
		errs.ForbiddenError().AppendDetails("原密码错误", "修改密码失败").Respond(c)
		return
	}

	pwdHash, e := crypto.HashArgon2ID(req.NewPassword)
	if e != nil {
		errs.CreateAndLogInternalError(e, "Failed to hash new password").AppendDetails("密码哈希失败", "修改密码失败").Respond(c)
		return
	}

	if err := user.UpsertUserPassword(c.Request.Context(), &model.UserPassword{
		UserID:   claims.UserID,
		Password: pwdHash,
	}); err != nil {
		err.AppendDetails("修改密码失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}
