package user

import (
	"context"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/user")
	i := internal.Group("/user")

	a.GET("/profile", middleware.RequireToken(), handling.Wrap("获取用户信息失败", getUserProfileByIDHandler))
	a.GET("/profile/id/:id", middleware.RequireToken(), handling.Wrap("获取用户信息失败", getUserProfileByIDHandler))
	a.GET("/profile/username/:username", middleware.RequireToken(), handling.Wrap("获取用户信息失败", getUserProfileByUsernameHandler))

	a.PATCH("/profile", middleware.RequireToken(), handling.Wrap("用户信息修改失败", updateUserProfileHandler))
	a.PATCH("/profile/id/:id", middleware.RequireToken(), handling.Wrap("用户信息修改失败", updateUserProfileHandler))

	a.GET("/avatar", middleware.RequireToken(), handling.Wrap("头像获取失败", getAvatarHandler))
	a.GET("/avatar/:id", middleware.RequireToken(), handling.Wrap("头像获取失败", getAvatarHandler))

	a.GET("/banner", middleware.RequireToken(), handling.Wrap("背景图获取失败", getBannerHandler))
	a.GET("/banner/:id", middleware.RequireToken(), handling.Wrap("背景图获取失败", getBannerHandler))

	a.PUT("/avatar", middleware.RequireToken(), middleware.LimitSize(5<<20), handling.Wrap("头像设置失败", setAvatarHandler))
	a.PUT("/avatar/:id", middleware.RequireToken(), middleware.LimitSize(5<<20), handling.Wrap("头像设置失败", setAvatarHandler))

	a.PUT("/banner", middleware.RequireToken(), middleware.LimitSize(5<<20), handling.Wrap("背景图设置失败", setBannerHandler))
	a.PUT("/banner/:id", middleware.RequireToken(), middleware.LimitSize(5<<20), handling.Wrap("背景图设置失败", setBannerHandler))

	a.DELETE("/avatar", middleware.RequireToken(), handling.Wrap("头像删除失败", deleteAvatarHandler))
	a.DELETE("/avatar/:id", middleware.RequireToken(), handling.Wrap("头像删除失败", deleteAvatarHandler))

	a.DELETE("/banner", middleware.RequireToken(), handling.Wrap("背景图删除失败", deleteBannerHandler))
	a.DELETE("/banner/:id", middleware.RequireToken(), handling.Wrap("背景图删除失败", deleteBannerHandler))

	a.GET("/search/info", middleware.RequirePermission(perm.PermUsersList), handling.Wrap("用户搜索失败", searchInfoHandler))
	a.POST("/search/query", middleware.RequirePermission(perm.PermUsersList), handling.Wrap("用户搜索失败", searchQueryHandler))

	i.GET("/ban/:id", middleware.RequireToken(), handling.Wrap("用户封禁信息获取失败", getUserBanHandler))
	i.POST("/ban/:id", middleware.RequirePermission(perm.PermUsersBanWrite), handling.Wrap("用户封禁失败", banUserHandler))
	i.DELETE("/ban/:id", middleware.RequirePermission(perm.PermUsersBanWrite), handling.Wrap("用户解封失败", unbanUserHandler))

	a.GET("/relation/list/following", handling.Wrap("关注列表获取失败", getFollowingsHandler))
	a.GET("/relation/list/followers", handling.Wrap("粉丝列表获取失败", getFollowersHandler))
	a.GET("/relation/list/friends", handling.Wrap("好友列表获取失败", getFriendsHandler))
	a.GET("/relation/list/following/:id", middleware.RequireToken(), handling.Wrap("关注列表获取失败", getFollowingsHandler))
	a.GET("/relation/list/followers/:id", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", getFollowersHandler))
	a.GET("/relation/list/friends/:id", middleware.RequireToken(), handling.Wrap("好友列表获取失败", getFriendsHandler))
	a.GET("/relation/count/following", handling.Wrap("关注列表获取失败", countFollowingsHandler))
	a.GET("/relation/count/followers", handling.Wrap("粉丝列表获取失败", countFollowersHandler))
	a.GET("/relation/count/friends", handling.Wrap("好友列表获取失败", countFriendsHandler))
	a.GET("/relation/count/following/:id", middleware.RequireToken(), handling.Wrap("关注列表获取失败", countFollowingsHandler))
	a.GET("/relation/count/followers/:id", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", countFollowersHandler))
	a.GET("/relation/count/friends/:id", middleware.RequireToken(), handling.Wrap("好友列表获取失败", countFriendsHandler))
	a.POST("/relation/follow/:id", handling.Wrap("关注失败", followUserHandler))
	a.DELETE("/relation/follow/:id", handling.Wrap("取消关注失败", unfollowUserHandler))
	a.GET("/relation/query/:id", middleware.RequirePermission(perm.PermUserRelationRead), handling.Wrap("关注关系获取失败", getFollowStatusHandler))
	i.POST("/relation/follow/:userID/:id", handling.Wrap("关注失败", followUserHandler))
	i.DELETE("/relation/follow/:userID/:id", handling.Wrap("取消关注失败", unfollowUserHandler))
}

func filterProfiles(ctx context.Context, claims *model.RegisteredTokenClaims, targetUsers ...*model.User) ([]gin.H, *errs.Error) {
	if claims == nil {
		return nil, errs.InvalidTokenError().AppendDetails("无效的令牌", "鉴权失败").Seal()
	}

	selfBasic := perm.HasPermission(claims, perm.PermUserProfileReadBasic)
	selfIdentity := perm.HasPermission(claims, perm.PermUserProfileReadIdentity)
	selfRealName := perm.HasPermission(claims, perm.PermUserProfileReadRealName)
	selfAbout := perm.HasPermission(claims, perm.PermUserProfileReadAbout)
	selfVisibilities := perm.HasPermission(claims, perm.PermUserProfileReadVisibilities)

	otherBasic := perm.HasPermission(claims, perm.PermUsersProfileReadBasic)
	otherIdentity := perm.HasPermission(claims, perm.PermUsersProfileReadIdentity)
	otherRealName := perm.HasPermission(claims, perm.PermUsersProfileReadRealName)
	otherRealNameAllowed := perm.HasPermission(claims, perm.PermUsersProfileReadRealNameAllowed)
	otherAbout := perm.HasPermission(claims, perm.PermUsersProfileReadAbout)
	otherVisibilities := perm.HasPermission(claims, perm.PermUsersProfileReadVisibilities)

	results := make([]gin.H, 0, len(targetUsers))
	for _, targetUser := range targetUsers {
		isSelf := claims.UserID == targetUser.ID

		var basic, identity, realName, about, visibilities bool
		if isSelf {
			basic, identity, realName, about, visibilities = selfBasic, selfIdentity, selfRealName, selfAbout, selfVisibilities
		} else {
			basic, identity, about, visibilities = otherBasic, otherIdentity, otherAbout, otherVisibilities
			if otherRealName {
				realName = true
			} else if !otherRealNameAllowed {
				realName = false
			} else {
				rel, err := user.GetFollowRelationship(ctx, claims.UserID, targetUser.ID)
				if err != nil {
					return nil, err
				}
				switch targetUser.Visibilities.RealName {
				case model.VisibilityPublic:
					realName = true
				case model.VisibilityFriends:
					realName = rel == model.RelationshipFriends
				default:
					realName = false
				}
			}
		}

		res := gin.H{"id": targetUser.ID}
		if basic {
			res["username"] = targetUser.Username
			res["nickname"] = targetUser.Nickname
			res["deleted"] = targetUser.DeletedAt.Valid
		}
		if identity {
			res["type"] = targetUser.Type
			res["school"] = targetUser.School
			res["student_num"] = targetUser.StudentNum
		}
		if realName {
			res["real_name"] = targetUser.RealName
		}
		if about {
			res["signature"] = targetUser.Signature
			res["bio"] = targetUser.Bio
		}
		if visibilities {
			res["visibilities"] = targetUser.Visibilities
		}
		results = append(results, res)
	}

	return results, nil
}
