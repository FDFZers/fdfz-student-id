package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"strconv"

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

	a.GET("/search/info", middleware.RequireToken(), handling.Wrap("用户搜索失败", SearchInfoHandler))
	a.POST("/search/query", middleware.RequireToken(), handling.Wrap("用户搜索失败", SearchQueryHandler))

	i.GET("/ban/:id", middleware.RequireToken(), handling.Wrap("用户封禁信息获取失败", getUserBanHandler))
	i.POST("/ban/:id", middleware.RequireToken(), handling.Wrap("用户封禁失败", banUserHandler))
	i.DELETE("/ban/:id", middleware.RequireToken(), handling.Wrap("用户解封失败", unbanUserHandler))

	a.POST("/follow/:id", middleware.RequireToken(), handling.Wrap("关注失败", followUserHandler))
	a.DELETE("/follow/:id", middleware.RequireToken(), handling.Wrap("取消关注失败", unfollowUserHandler))
	a.GET("/follow/:id", middleware.RequireToken(), handling.Wrap("关注关系获取失败", getFollowStatusHandler))
	a.GET("/followers", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", getFollowersHandler))
	a.GET("/followers/:id", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", getFollowersHandler))
	a.GET("/following", middleware.RequireToken(), handling.Wrap("关注列表获取失败", getFollowingHandler))
	a.GET("/following/:id", middleware.RequireToken(), handling.Wrap("关注列表获取失败", getFollowingHandler))
	a.GET("/friends", middleware.RequireToken(), handling.Wrap("好友列表获取失败", getFriendsHandler))
	a.GET("/friends/:id", middleware.RequireToken(), handling.Wrap("好友列表获取失败", getFriendsHandler))
}

func ResolveTargetID(c *gin.Context, selfID int64) (int64, *errs.Error) {
	targetStr := c.Param("id")
	if targetStr == "" {
		return selfID, nil
	}
	target, err := strconv.ParseInt(targetStr, 10, 64)
	if err != nil {
		return 0, errs.BadRequestError().AppendDetails("无效的用户 ID")
	}
	return target, nil
}

func EnsureUserExists(c *gin.Context, userID int64) *errs.Error {
	target, err := user.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		return err
	} else if target == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}
	return nil
}

type profileEntry struct {
	Key      string
	IsPublic bool
	Value    any
}

func filterProfiles(claims *model.RegisteredTokenClaims, targetUsers ...*model.User) []gin.H {
	hasPublicPerm := perm.Contains(claims.Permissions, "student_id.user.profile.public.read")

	type fieldPerm struct {
		hasRead bool
		hasSelf bool
	}
	fieldKeys := [...]string{
		"id", "username", "nickname", "real_name",
		"school", "student_num", "bio", "signature", "type", "deleted",
		"visibilities",
	}
	var permCache [len(fieldKeys)]fieldPerm
	for i, key := range fieldKeys {
		permCache[i] = fieldPerm{
			hasRead: perm.Contains(claims.Permissions, "student_id.user.profile."+key+".read"),
			hasSelf: perm.Contains(claims.Permissions, "student_id.user.profile."+key+".read.self"),
		}
	}

	results := make([]gin.H, 0, len(targetUsers))
	for _, targetUser := range targetUsers {
		isSelf := claims.UserID == targetUser.ID
		realNamePublic := targetUser.Visibilities.RealName == model.VisibilityPublic

		values := []profileEntry{
			{"id", true, targetUser.ID},
			{"username", true, targetUser.Username},
			{"nickname", true, targetUser.Nickname},
			{"real_name", realNamePublic, targetUser.RealName},
			{"school", true, targetUser.School},
			{"student_num", true, targetUser.StudentNum},
			{"bio", true, targetUser.Bio},
			{"signature", true, targetUser.Signature},
			{"type", true, targetUser.Type},
			{"deleted", true, targetUser.DeletedAt.Valid},
			{"visibilities", false, targetUser.Visibilities},
		}

		res := make(gin.H, len(values))
		for i, value := range values {
			pc := permCache[i]
			canRead := (value.IsPublic && hasPublicPerm) ||
				(isSelf && pc.hasSelf) ||
				pc.hasRead
			if canRead {
				res[value.Key] = value.Value
			}
		}
		results = append(results, res)
	}

	return results
}
