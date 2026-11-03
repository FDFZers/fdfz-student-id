package user

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// 关注 / 取消关注 / 关注关系
// ---------------------------------------------------------------------------

func followUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserRelationWrite)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersRelationWrite)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	if err := user.FollowUser(c.Request.Context(), selfID, targetID); err != nil {
		return err
	}

	rel, err := user.GetFollowRelationship(c.Request.Context(), selfID, targetID)
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, gin.H{
		"relationship": rel,
	})
	return nil
}

func unfollowUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserRelationWrite)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersRelationWrite)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	if err := user.UnfollowUser(c.Request.Context(), selfID, targetID); err != nil {
		return err
	}

	rel, err := user.GetFollowRelationship(c.Request.Context(), selfID, targetID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"relationship": rel,
	})
	return nil
}

func getFollowStatusHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	rel, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, targetID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"relationship": rel,
	})
	return nil
}

// ---------------------------------------------------------------------------
// 粉丝 / 关注 / 好友列表
// ---------------------------------------------------------------------------

func getFollowersHandler(c *gin.Context) *errs.Error {
	return serveFollowList(c, model.RelationshipFollowed)
}

func getFollowingsHandler(c *gin.Context) *errs.Error {
	return serveFollowList(c, model.RelationshipFollowing)
}

func getFriendsHandler(c *gin.Context) *errs.Error {
	return serveFollowList(c, model.RelationshipFriends)
}

func countFollowersHandler(c *gin.Context) *errs.Error {
	return serveFollowCount(c, model.RelationshipFollowed)
}

func countFollowingsHandler(c *gin.Context) *errs.Error {
	return serveFollowCount(c, model.RelationshipFollowing)
}

func countFriendsHandler(c *gin.Context) *errs.Error {
	return serveFollowCount(c, model.RelationshipFriends)
}

func serveFollowList(c *gin.Context, rel model.Relationship) *errs.Error {
	claims := handling.MustGetClaims(c)

	target, err := resolveFollowListTarget(c, claims)
	if err != nil {
		return err
	}

	limit, offset := search.ParseQueryPagination(c)

	if err := canViewFollowList(c, claims, target, rel); err != nil {
		return err
	}

	var list *model.RelationList
	switch rel {
	case model.RelationshipFollowed:
		list, err = user.ListFollowers(c.Request.Context(), target.ID, limit, offset)
	case model.RelationshipFollowing:
		list, err = user.ListFollowing(c.Request.Context(), target.ID, limit, offset)
	case model.RelationshipFriends:
		list, err = user.ListFriends(c.Request.Context(), target.ID, limit, offset)
	default:
		return errs.CreateAndLogInternalError(errors.New("unknown follow list type"), "Unknown follow list type").AppendDetails("未知的关注列表类型")
	}
	if err != nil {
		return err
	}

	filtered, err := filterProfiles(c.Request.Context(), claims, list.Users...)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": list.Count,
		"data":  filtered,
	})
	return nil
}

func serveFollowCount(c *gin.Context, rel model.Relationship) *errs.Error {
	claims := handling.MustGetClaims(c)

	target, err := resolveFollowListTarget(c, claims)
	if err != nil {
		return err
	}

	if err := canViewFollowList(c, claims, target, rel); err != nil {
		return err
	}

	var count int64
	switch rel {
	case model.RelationshipFollowed:
		count, err = user.CountFollowers(c.Request.Context(), target.ID)
	case model.RelationshipFollowing:
		count, err = user.CountFollowing(c.Request.Context(), target.ID)
	case model.RelationshipFriends:
		count, err = user.CountFriends(c.Request.Context(), target.ID)
	default:
		return errs.CreateAndLogInternalError(errors.New("unknown follow list type"), "Unknown follow list type").AppendDetails("未知的关注列表类型")
	}
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": count,
	})
	return nil
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

func resolveFollowListTarget(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
) (*model.User, *errs.Error) {
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return nil, err
	}

	target, err := user.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		return nil, err
	} else if target == nil {
		return nil, errs.NotFoundError().AppendDetails("用户不存在")
	}
	return target, nil
}

func canViewFollowList(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
	target *model.User,
	rel model.Relationship,
) *errs.Error {
	if perm.HasPermission(claims, perm.PermUsersRelationRead) {
		return nil
	}

	if claims.UserID == target.ID {
		if !perm.HasPermission(claims, perm.PermUserRelationRead) {
			return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
		}
		return nil
	}

	if !perm.HasPermission(claims, perm.PermUsersRelationReadAllowed) {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
	}

	var visibilities []model.Visibility
	switch rel {
	case model.RelationshipFollowed:
		visibilities = []model.Visibility{target.Visibilities.Followers}
	case model.RelationshipFollowing:
		visibilities = []model.Visibility{target.Visibilities.Following}
	case model.RelationshipFriends:
		visibilities = []model.Visibility{target.Visibilities.Followers, target.Visibilities.Following}
	default:
		return errs.CreateAndLogInternalError(errors.New("unknown follow relationship type"), "Unknown follow relationship type").AppendDetails("未知的关注关系类型")
	}

	var r *model.Relationship
	for _, visibility := range visibilities {
		switch visibility {
		case model.VisibilityPublic:
			continue
		case model.VisibilityFriends:
			if r == nil {
				rel, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, target.ID)
				if err != nil {
					return err
				}
				r = &rel
			}
			if *r != model.RelationshipFriends {
				return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
			}
			continue
		default:
			return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败")
		}
	}
	return nil
}
