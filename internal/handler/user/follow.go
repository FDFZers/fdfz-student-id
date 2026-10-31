//go:generate go tool go-enum --names --values --marshal --sql
package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func errorMessage(rel *model.FollowRelationship) string {
	switch *rel {
	case model.FollowRelationshipFollowed:
		return "粉丝列表获取失败"
	case model.FollowRelationshipFollowing:
		return "关注列表获取失败"
	case model.FollowRelationshipFriends:
		return "好友列表获取失败"
	}
	return "未知列表"
}

// ---------------------------------------------------------------------------
// 关注 / 取消关注 / 关注关系
// ---------------------------------------------------------------------------

func followUserHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails("关注失败").Respond(c)
		return
	}
	if targetID == claims.UserID {
		errs.BadRequestError().AppendDetails("不能关注自己", "关注失败").Respond(c)
		return
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		err.AppendDetails("关注失败").Respond(c)
		return
	}

	if err := user.FollowUser(c.Request.Context(), claims.UserID, targetID); err != nil {
		err.AppendDetails("关注失败").Respond(c)
		return
	}
	rel, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, targetID)
	if err != nil {
		err.AppendDetails("关注失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"relationship": rel,
	})
}

func unfollowUserHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails("取消关注失败").Respond(c)
		return
	}
	if targetID == claims.UserID {
		errs.BadRequestError().AppendDetails("不能取消关注自己", "取消关注失败").Respond(c)
		return
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		err.AppendDetails("取消关注失败").Respond(c)
		return
	}

	if err := user.UnfollowUser(c.Request.Context(), claims.UserID, targetID); err != nil {
		err.AppendDetails("取消关注失败").Respond(c)
		return
	}

	rel, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, targetID)
	if err != nil {
		err.AppendDetails("取消关注失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"relationship": rel,
	})
}

func getFollowStatusHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails("关注关系获取失败").Respond(c)
		return
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		err.AppendDetails("关注关系获取失败").Respond(c)
		return
	}

	rel, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, targetID)
	if err != nil {
		err.AppendDetails("关注关系获取失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"relationship": rel,
	})
}

// ---------------------------------------------------------------------------
// 粉丝 / 关注 / 好友列表
// ---------------------------------------------------------------------------

func getFollowersHandler(c *gin.Context) {
	serveFollowList(c, model.FollowRelationshipFollowed)
}

func getFollowingHandler(c *gin.Context) {
	serveFollowList(c, model.FollowRelationshipFollowing)
}

func getFriendsHandler(c *gin.Context) {
	serveFollowList(c, model.FollowRelationshipFriends)
}

func serveFollowList(c *gin.Context, rel model.FollowRelationship) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	errMsg := errorMessage(&rel)

	target, err := resolveFollowListTarget(c, claims)
	if err != nil {
		err.AppendDetails(errMsg).Respond(c)
		return
	}

	limit, offset, ok := parseFollowListPagination(c)
	if !ok {
		errs.BadRequestError().AppendDetails("无效的分页参数", errMsg)
		return
	}

	if err := canViewFollowList(c, claims, target, rel); err != nil {
		err.AppendDetails(errMsg).Respond(c)
		return
	}

	var list *model.FollowList
	switch rel {
	case model.FollowRelationshipFollowed:
		list, err = user.ListFollowers(c.Request.Context(), target.ID, limit, offset)
	case model.FollowRelationshipFollowing:
		list, err = user.ListFollowing(c.Request.Context(), target.ID, limit, offset)
	case model.FollowRelationshipFriends:
		list, err = user.ListFriends(c.Request.Context(), target.ID, limit, offset)
	default:
		list = &model.FollowList{}
		err = errs.InternalError().AppendDetails("未知的关注列表类型")
	}
	if err != nil {
		err.AppendDetails(errMsg).Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"count": list.Count,
		"data":  filterProfiles(claims, list.Users...),
	})
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

func resolveFollowListTarget(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
) (*model.User, *errs.Error) {
	targetID := claims.UserID
	if idStr := c.Param("id"); idStr != "" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			return nil, errs.BadRequestError().AppendDetails("无效的用户 ID")
		}
		targetID = id
	}

	target, err := user.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		return nil, err
	} else if target == nil {
		return nil, errs.NotFoundError().AppendDetails("用户不存在")
	}
	return target, nil
}

func parseFollowListPagination(c *gin.Context) (limit, offset int32, ok bool) {
	limit = user.FollowListDefaultLimit
	if raw := c.Query("limit"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || v <= 0 || int32(v) > user.FollowListMaxLimit {
			return 0, 0, false
		}
		limit = int32(v)
	}

	offset = 0
	if raw := c.Query("offset"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || v < 0 {
			return 0, 0, false
		}
		offset = int32(v)
	}

	return limit, offset, true
}

func canViewFollowList(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
	target *model.User,
	rel model.FollowRelationship,
) *errs.Error {
	if claims.UserID == target.ID {
		return nil
	}
	if perm.Contains(claims.Permissions, "student_id.users.list") {
		return nil
	}

	if rel == model.FollowRelationshipFriends {
		r, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, target.ID)
		if err != nil {
			return err
		}
		if r != model.FollowRelationshipFriends {
			return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
		}
		return nil
	}

	var visibility model.Visibility
	switch rel {
	case model.FollowRelationshipFollowed:
		visibility = target.Visibilities.Followers
	case model.FollowRelationshipFollowing:
		visibility = target.Visibilities.Following
	default:
		return errs.InternalError().AppendDetails("未知的关注关系类型")
	}

	switch visibility {
	case model.VisibilityPublic:
		return nil
	case model.VisibilityFriends:
		r, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, target.ID)
		if err != nil {
			return err
		}
		if r != model.FollowRelationshipFriends {
			return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
		}
		return nil
	default:
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
	}
}
