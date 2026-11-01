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
		return nil, err.AppendDetails("密码重置初始化失败")
	}
	return session, nil
}

type resetPasswordEmailInitReq struct {
	Email         string `json:"email"`
	AltchaPayload string `json:"altcha_payload"`
}

func resetPasswordEmailInitHandler(c *gin.Context) {
	var req resetPasswordEmailInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "密码重置初始化失败").Respond(c)
		return
	}
	if err := captcha.VerifyPayloadStr(req.AltchaPayload); err != nil {
		err.AppendDetails("密码重置初始化失败").Respond(c)
		return
	}

	usr, err := user.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		err.AppendDetails("密码重置初始化失败").Respond(c)
		return
	} else if usr == nil {
		if session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{}); err != nil {
			err.Respond(c)
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"session_id": session.ID,
				"2fa":        []string{"email"},
			})
			return
		}
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		err.AppendDetails("密码重置初始化失败").Respond(c)
		return
	} else if ban != nil {
		if session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{}); err != nil {
			err.Respond(c)
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"session_id": session.ID,
				"2fa":        []string{"email"},
			})
			return
		}
	}

	if session, err := createPasswordResetAuthSession(c.Request.Context(), usr.ID, null.StringFrom(req.Email), null.String{}); err != nil {
		err.Respond(c)
		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"session_id": session.ID,
			"2fa":        []string{"email"},
		})
		return
	}
}

type resetPasswordQQInitReq struct {
	QQ            string `json:"qq"`
	AltchaPayload string `json:"altcha_payload"`
}

func resetPasswordQQInitHandler(c *gin.Context) {
	var req resetPasswordQQInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "密码重置初始化失败").Respond(c)
		return
	}
	if err := captcha.VerifyPayloadStr(req.AltchaPayload); err != nil {
		err.AppendDetails("密码重置初始化失败").Respond(c)
		return
	}

	usr, err := user.GetUserByQQ(c.Request.Context(), req.QQ)
	if err != nil {
		err.AppendDetails("密码重置初始化失败").Respond(c)
		return
	} else if usr == nil {
		if session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{}); err != nil {
			err.Respond(c)
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"session_id": session.ID,
				"2fa":        []string{"qq"},
			})
			return
		}
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		err.AppendDetails("密码重置初始化失败").Respond(c)
		return
	} else if ban != nil {
		if session, err := createPasswordResetAuthSession(c.Request.Context(), 0, null.String{}, null.String{}); err != nil {
			err.Respond(c)
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"session_id": session.ID,
				"2fa":        []string{"qq"},
			})
			return
		}
	}

	if session, err := createPasswordResetAuthSession(c.Request.Context(), usr.ID, null.String{}, null.StringFrom(req.QQ)); err != nil {
		err.Respond(c)
		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"session_id": session.ID,
			"2fa":        []string{"qq"},
		})
		return
	}
}

type resetPasswordFinalizeReq struct {
	SessionID uuid.UUID `json:"session_id"`
	Password  string    `json:"password"`
}

func resetPasswordFinalizeHandler(c *gin.Context) {
	var req resetPasswordFinalizeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "密码重置失败").Respond(c)
		return
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("密码重置失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "密码重置失败").Respond(c)
		return
	}

	if session.Type != auth.AuthSessionTypeResetPassword {
		errs.BadRequestError().AppendDetails("鉴权会话类型错误", "密码重置失败").Respond(c)
		return
	}
	if !session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证未通过", "密码重置失败").Respond(c)
		return
	}
	if session.UserID == 0 {
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	ban, err := user.GetUserBan(c.Request.Context(), session.UserID)
	if err != nil {
		err.AppendDetails("密码重置失败").Respond(c)
		return
	}
	if ban != nil {
		handling.RespondBanned(c, ban, "密码重置失败")
		return
	}

	pwdHash, e := crypto.HashArgon2ID(req.Password)
	if e != nil {
		errs.CreateAndLogInternalError(e, "Failed to hash new password").AppendDetails("密码哈希失败", "密码重置失败").Respond(c)
		return
	}

	if err := user.UpsertUserPassword(c.Request.Context(), &model.UserPassword{
		UserID:   session.UserID,
		Password: pwdHash,
	}); err != nil {
		err.AppendDetails("密码重置失败").Respond(c)
		return
	}

	if err := auth.DeleteAuthSession(c.Request.Context(), session); err != nil {
		slog.Warn("Failed to delete password reset auth session", "error", err.Info.Error, "session_id", session.ID)
	}

	c.JSON(http.StatusOK, gin.H{})
}
