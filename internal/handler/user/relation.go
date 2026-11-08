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

// followUserHandler 关注用户：校验权限、目标用户存在后写入关注关系，并返回更新后的关注关系。
// 内部接口可通过 :userID 代他人关注，此时需要 users.relation.write；自己关注需要 user.relation.write。
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
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
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

// unfollowUserHandler 取消关注：校验权限、目标用户存在后删除关注关系，并返回更新后的关注关系。
// 未关注时视为成功（幂等）；内部接口可通过 :userID 代他人取消关注。
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
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
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

// getFollowStatusHandler 查询当前登录用户与指定用户之间的关注关系，返回 none/followed/following/friends。
// 需要 user.relation.read 权限；目标用户不存在时返回 404。
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

// getFollowersHandler 获取粉丝列表（关注目标用户的人）。
func getFollowersHandler(c *gin.Context) *errs.Error {
	return serveFollowList(c, model.RelationshipFollowed)
}

// getFollowingsHandler 获取关注列表（目标用户关注的人）。
func getFollowingsHandler(c *gin.Context) *errs.Error {
	return serveFollowList(c, model.RelationshipFollowing)
}

// getFriendsHandler 获取好友列表（与目标用户互相关注的人）。
func getFriendsHandler(c *gin.Context) *errs.Error {
	return serveFollowList(c, model.RelationshipFriends)
}

// countFollowersHandler 获取粉丝数。
func countFollowersHandler(c *gin.Context) *errs.Error {
	return serveFollowCount(c, model.RelationshipFollowed)
}

// countFollowingsHandler 获取关注数。
func countFollowingsHandler(c *gin.Context) *errs.Error {
	return serveFollowCount(c, model.RelationshipFollowing)
}

// countFriendsHandler 获取好友数。
func countFriendsHandler(c *gin.Context) *errs.Error {
	return serveFollowCount(c, model.RelationshipFriends)
}

// serveFollowList 获取关系列表的统一实现：解析目标用户与分页、校验可见性后按关系类型查询并过滤资料。
// 列表项会经过 filterProfiles，因此返回字段仍受调用方权限与各用户 visibilities 约束。
func serveFollowList(c *gin.Context, rel model.Relationship) *errs.Error {
	claims := handling.MustGetClaims(c)

	// 解析目标用户（缺省为自己）与分页参数

	target, err := resolveFollowListTarget(c, claims)
	if err != nil {
		return err
	}

	limit, offset := search.ParseQueryPagination(c)

	if err := canViewFollowList(c, claims, target, rel); err != nil {
		return err
	}

	// 按关系类型查询列表；总数由列表接口一并返回

	var list *model.RelationList
	switch rel {
	case model.RelationshipFollowed:
		list, err = user.ListFollowers(c.Request.Context(), target.ID, limit, offset)
	case model.RelationshipFollowing:
		list, err = user.ListFollowing(c.Request.Context(), target.ID, limit, offset)
	case model.RelationshipFriends:
		list, err = user.ListFriends(c.Request.Context(), target.ID, limit, offset)
	default:
		return errs.CreateAndLogInternalError(errors.New("unknown follow list type"), "Unknown follow list type").AppendDetails("关注列表类型不受支持")
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

// serveFollowCount 获取关系计数的统一实现：解析目标用户并校验可见性后按关系类型查询计数。
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
		return errs.CreateAndLogInternalError(errors.New("unknown follow list type"), "Unknown follow list type").AppendDetails("关注列表类型不受支持")
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

// resolveFollowListTarget 解析关系列表/计数接口的目标用户：路径参数缺省时为自己，目标不存在时返回 404。
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

// canViewFollowList 判定调用方能否查看目标用户的某类关系列表：管理员直接放行，
// 查看自己需要 user.relation.read，查看他人需要 users.relation.read.allowed 且满足目标用户的 visibilities。
// 注意：好友列表要求 followers 与 following 两个可见性都允许；friends 可见性需要查询双方的关注关系。
func canViewFollowList(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
	target *model.User,
	rel model.Relationship,
) *errs.Error {
	// 拥有 users.relation.read 时不受可见性限制

	if perm.HasPermission(claims, perm.PermUsersRelationRead) {
		return nil
	}

	// 查看自己的关系列表只需要 user.relation.read

	if claims.UserID == target.ID {
		if !perm.HasPermission(claims, perm.PermUserRelationRead) {
			return errs.PermissionDeniedError().AppendDetails("权限不足")
		}
		return nil
	}

	// 查看他人时按目标用户的 visibilities 判定

	if !perm.HasPermission(claims, perm.PermUsersRelationReadAllowed) {
		return errs.PermissionDeniedError().AppendDetails("权限不足")
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
		return errs.CreateAndLogInternalError(errors.New("unknown follow relationship type"), "Unknown follow relationship type").AppendDetails("关注关系类型不受支持")
	}

	var r *model.Relationship
	for _, visibility := range visibilities {
		switch visibility {
		case model.VisibilityPublic:
			continue
		case model.VisibilityFriends:
			// 多个可见性可能都要查关系，只查询一次
			if r == nil {
				rel, err := user.GetFollowRelationship(c.Request.Context(), claims.UserID, target.ID)
				if err != nil {
					return err
				}
				r = &rel
			}
			if *r != model.RelationshipFriends {
				return errs.PermissionDeniedError().AppendDetails("权限不足")
			}
			continue
		default:
			return errs.PermissionDeniedError().AppendDetails("权限不足")
		}
	}
	return nil
}
