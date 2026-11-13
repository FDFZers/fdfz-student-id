package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// currentSessionUUID 解析当前请求令牌所属的登录会话 UUID。
// 注意：提权令牌在 SessionID 中携带会话 UUID，访问令牌则只有 JWT ID，故需回退到 claims.ID。
func currentSessionUUID(claims *model.RegisteredTokenClaims) *uuid.UUID {
	if claims.SessionID.Valid {
		if id, err := uuid.Parse(claims.SessionID.String); err == nil {
			return &id
		}
	}
	if id, err := uuid.Parse(claims.ID); err == nil {
		return &id
	}
	return nil
}

// serveUserSessionList 查询目标用户的有效会话并输出；仅当查看自己时标记当前会话。
func serveUserSessionList(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
	targetID int64,
) *errs.Error {
	sessions, err := authsvc.ListUserSessions(c.Request.Context(), targetID)
	if err != nil {
		return err
	}

	var currentID *uuid.UUID
	if targetID == claims.UserID {
		currentID = currentSessionUUID(claims)
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": handling.SessionInfos(sessions, currentID),
	})
	return nil
}

// listSessionsHandler 列出用户的有效会话：查看自己需 user.session.read，查看他人需 users.session.read。
func listSessionsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	// 自己与他人的会话读取使用不同权限
	var allowed bool
	if selfID == claims.UserID {
		allowed = permsvc.HasPermission(claims, permsvc.PermUserSessionRead)
	} else {
		allowed = permsvc.HasPermission(claims, permsvc.PermUsersSessionRead)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	return serveUserSessionList(c, claims, selfID)
}

// revokeSessionsHandler 撤销目标用户的全部会话与提权令牌；撤销自己时同时清理 Cookie。
// 注意：撤销只影响后续刷新与提权校验，已签发的访问令牌在过期前仍然有效。
func revokeSessionsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	// 撤销自己的会话需提权令牌（提权令牌不携带权限），撤销他人需 users.session.write。
	var allowed bool
	if selfID == claims.UserID {
		allowed = claims.TokenType == model.TokenTypeStepup
	} else {
		allowed = permsvc.HasPermission(claims, permsvc.PermUsersSessionWrite)
	}
	if !allowed {
		if selfID == claims.UserID {
			return errs.PermissionDeniedError().AppendDetails("撤销自己的会话需要提权令牌").Seal()
		}
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	// 撤销全部会话后提权令牌也无存在的意义，一并失效
	if err := authsvc.RevokeAllUserSessions(c.Request.Context(), selfID); err != nil {
		return err
	}
	if err := authsvc.RevokeUserStepups(c.Request.Context(), selfID); err != nil {
		return err
	}

	if selfID == claims.UserID {
		handling.ClearSessionCookies(c)
	}

	handling.RespondOK(c)
	return nil
}

// revokeSessionHandler 撤销目标用户指定的单个会话；不允许撤销不属于目标用户的会话。
// 注意：撤销只影响后续刷新与提权校验，已签发的访问令牌在过期前仍然有效。
func revokeSessionHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	// 撤销自己的会话需提权令牌（提权令牌不携带权限），撤销他人需 users.session.write。
	var allowed bool
	if selfID == claims.UserID {
		allowed = claims.TokenType == model.TokenTypeStepup
	} else {
		allowed = permsvc.HasPermission(claims, permsvc.PermUsersSessionWrite)
	}
	if !allowed {
		if selfID == claims.UserID {
			return errs.PermissionDeniedError().AppendDetails("撤销自己的会话需要提权令牌").Seal()
		}
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	// 解析会话 ID 并校验归属与有效性
	sessionID, e := uuid.Parse(c.Param("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("会话 ID 格式错误")
	}

	session, err := authsvc.GetSessionByUUID(c.Request.Context(), sessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return errs.NotFoundError().AppendDetails("会话不存在")
	}
	if session.UserID != selfID {
		return errs.NotFoundError().AppendDetails("会话不存在")
	}
	if session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		return errs.NotFoundError().AppendDetails("会话不存在或已失效")
	}

	if err := authsvc.RevokeSession(c.Request.Context(), sessionID); err != nil {
		return err
	}

	// 撤销的是当前会话时清理 Cookie，避免客户端继续携带失效会话
	if currentID := currentSessionUUID(claims); currentID != nil && sessionID == *currentID {
		handling.ClearSessionCookies(c)
	}

	handling.RespondOK(c)
	return nil
}
