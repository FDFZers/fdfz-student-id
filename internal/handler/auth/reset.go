package auth

import (
	"context"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

// createPasswordResetAuthSession 创建密码重置用鉴权会话并写入 Redis。
// userID 为 0 表示邮箱/QQ 未匹配到账号（或账号已封禁），用于返回与正常流程一致的响应，防止账号枚举。
// 注意：这里用 UpdateAuthSession 而非 CreateAuthSession，因为会话由调用方预先填好 ID 与验证方式。
func createPasswordResetAuthSession(ctx context.Context, userID int64, email, qq null.String) (*auth.AuthSession, *errs.Error) {
	session := &auth.AuthSession{
		ID:     uuid.New(),
		Type:   auth.AuthSessionTypeResetPassword,
		UserID: userID,
		Email:  email,
		QQ:     qq,
	}
	if err := auth.UpdateAuthSession(ctx, session, false); err != nil {
		return nil, err
	}
	return session, nil
}

// resetPasswordEmailInitReq 是邮箱密码重置初始化的请求体。
type resetPasswordEmailInitReq struct {
	Email         string `json:"email"`          // 待验证的邮箱
	AltchaPayload string `json:"altcha_payload"` // Altcha 人机验证载荷
}

// resetPasswordEmailInitHandler 校验 Altcha 后按邮箱创建密码重置鉴权会话，返回会话 ID 与可用验证方式。
// 注意：账号不存在或已封禁时也会创建匿名会话并返回相同结构，防止通过响应差异枚举账号。
func resetPasswordEmailInitHandler(c *gin.Context) *errs.Error {
	var req resetPasswordEmailInitReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := captcha.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

	// 存疑：这里未校验邮箱格式，非法输入会走「账号不存在」分支并静默成功。
	usr, err := user.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		return err
	} else if usr == nil {
		session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{})
		if err != nil {
			return err
		}
		c.JSON(http.StatusOK, gin.H{
			"session_id": session.ID,
			"2fa":        []string{"email"},
		})
		return nil
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		return err
	} else if ban != nil {
		session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{})
		if err != nil {
			return err
		}
		c.JSON(http.StatusOK, gin.H{
			"session_id": session.ID,
			"2fa":        []string{"email"},
		})
		return nil
	}

	session, err := createPasswordResetAuthSession(c.Request.Context(), usr.ID, null.StringFrom(req.Email), null.String{})
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": session.ID,
		"2fa":        []string{"email"},
	})
	return nil
}

// resetPasswordQQInitReq 是 QQ 密码重置初始化的请求体。
type resetPasswordQQInitReq struct {
	QQ            string `json:"qq"`             // 待验证的 QQ 号
	AltchaPayload string `json:"altcha_payload"` // Altcha 人机验证载荷
}

// resetPasswordQQInitHandler 校验 Altcha 后按 QQ 创建密码重置鉴权会话，返回会话 ID 与可用验证方式。
// 注意：账号不存在或已封禁时同样返回匿名会话，防止账号枚举。
func resetPasswordQQInitHandler(c *gin.Context) *errs.Error {
	var req resetPasswordQQInitReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := captcha.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

	// 存疑：这里未校验 QQ 号格式，非法输入会走「账号不存在」分支并静默成功。
	usr, err := user.GetUserByQQ(c.Request.Context(), req.QQ)
	if err != nil {
		return err
	} else if usr == nil {
		session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{})
		if err != nil {
			return err
		}
		c.JSON(http.StatusOK, gin.H{
			"session_id": session.ID,
			"2fa":        []string{"qq"},
		})
		return nil
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		return err
	} else if ban != nil {
		session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{})
		if err != nil {
			return err
		}
		c.JSON(http.StatusOK, gin.H{
			"session_id": session.ID,
			"2fa":        []string{"qq"},
		})
		return nil
	}

	session, err := createPasswordResetAuthSession(c.Request.Context(), usr.ID, null.String{}, null.StringFrom(req.QQ))
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": session.ID,
		"2fa":        []string{"qq"},
	})
	return nil
}

// resetPasswordFinalizeReq 是密码重置完成的请求体。
type resetPasswordFinalizeReq struct {
	SessionID uuid.UUID `json:"session_id"` // 密码重置初始化返回的鉴权会话 ID
	Password  string    `json:"password"`   // 新密码
}

// resetPasswordFinalizeHandler 在二次验证通过后设置新密码，并强制撤销该用户全部会话与提权令牌。
// 注意：匿名会话（UserID=0，账号不存在或已封禁）直接返回成功，不修改任何账号。
func resetPasswordFinalizeHandler(c *gin.Context) *errs.Error {
	var req resetPasswordFinalizeReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	// 校验鉴权会话状态
	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Type != auth.AuthSessionTypeResetPassword {
		return errs.BadRequestError().AppendDetails("鉴权会话类型错误")
	}
	if !session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证未通过")
	}
	if session.UserID == 0 {
		c.JSON(http.StatusOK, gin.H{})
		return nil
	}

	ban, err := user.GetUserBan(c.Request.Context(), session.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 校验并哈希新密码
	if err := handling.ValidatePassword(req.Password); err != nil {
		return err
	}

	pwdHash, e := crypto.HashArgon2ID(req.Password)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to hash new password").AppendDetails("密码哈希失败")
	}

	if err := user.UpsertUserPassword(c.Request.Context(), &model.UserPassword{
		UserID:   session.UserID,
		Password: pwdHash,
	}); err != nil {
		return err
	}

	// 重置密码后强制撤销全部会话与提权令牌
	if err := auth.RevokeAllUserSessions(c.Request.Context(), session.UserID); err != nil {
		return err
	}
	if err := auth.RevokeUserStepups(c.Request.Context(), session.UserID); err != nil {
		return err
	}
	handling.ClearSessionCookies(c)

	if err := auth.DeleteAuthSession(c.Request.Context(), session); err != nil {
		slog.Warn("Failed to delete password reset auth session", "error", err.Info.Error, "session_id", session.ID)
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
