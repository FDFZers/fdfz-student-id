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

func createPasswordResetAuthSession(ctx context.Context, userID int64, email, qq null.String) (*auth.AuthSession, *errs.Error) {
	session := &auth.AuthSession{
		ID:     uuid.New(),
		Type:   auth.AuthSessionTypeResetPassword,
		UserID: userID,
		Email:  email,
		QQ:     qq,
	}
	if err := auth.UpdateAuthSession(ctx, session, false); err != nil {
		return nil, err.AppendDetails("密码重置初始化失败").Seal()
	}
	return session, nil
}

type resetPasswordEmailInitReq struct {
	Email         string `json:"email"`
	AltchaPayload string `json:"altcha_payload"`
}

func resetPasswordEmailInitHandler(c *gin.Context) *errs.Error {
	var req resetPasswordEmailInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := captcha.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

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

type resetPasswordQQInitReq struct {
	QQ            string `json:"qq"`
	AltchaPayload string `json:"altcha_payload"`
}

func resetPasswordQQInitHandler(c *gin.Context) *errs.Error {
	var req resetPasswordQQInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := captcha.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

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

type resetPasswordFinalizeReq struct {
	SessionID uuid.UUID `json:"session_id"`
	Password  string    `json:"password"`
}

func resetPasswordFinalizeHandler(c *gin.Context) *errs.Error {
	var req resetPasswordFinalizeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

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

	// 重置密码后强制撤销全部会话
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
