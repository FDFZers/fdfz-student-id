package user

import (
	"fdfz-student-id/internal/middleware"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册用户域全部路由：api 为用户侧接口，internal 为内部管理接口。
// 端点级失败文案由各路由的 handling.Wrap 追加，处理器内部只追加具体原因。
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

	a.GET("/search/info", middleware.RequirePermission(permsvc.PermUsersList), handling.Wrap("用户搜索失败", searchInfoHandler))
	a.POST("/search/query", middleware.RequirePermission(permsvc.PermUsersList), handling.Wrap("用户搜索失败", searchQueryHandler))

	i.GET("/ban/:id", middleware.RequireToken(), handling.Wrap("用户封禁信息获取失败", getUserBanHandler))
	i.POST("/ban/:id", middleware.RequirePermission(permsvc.PermUsersBanWrite), handling.Wrap("用户封禁失败", banUserHandler))
	i.DELETE("/ban/:id", middleware.RequirePermission(permsvc.PermUsersBanWrite), handling.Wrap("用户解封失败", unbanUserHandler))

	a.GET("/relation/list/following", middleware.RequireToken(), handling.Wrap("关注列表获取失败", getFollowingsHandler))
	a.GET("/relation/list/followers", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", getFollowersHandler))
	a.GET("/relation/list/friends", middleware.RequireToken(), handling.Wrap("好友列表获取失败", getFriendsHandler))
	a.GET("/relation/list/following/:id", middleware.RequireToken(), handling.Wrap("关注列表获取失败", getFollowingsHandler))
	a.GET("/relation/list/followers/:id", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", getFollowersHandler))
	a.GET("/relation/list/friends/:id", middleware.RequireToken(), handling.Wrap("好友列表获取失败", getFriendsHandler))
	a.GET("/relation/count/following", middleware.RequireToken(), handling.Wrap("关注列表获取失败", countFollowingsHandler))
	a.GET("/relation/count/followers", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", countFollowersHandler))
	a.GET("/relation/count/friends", middleware.RequireToken(), handling.Wrap("好友列表获取失败", countFriendsHandler))
	a.GET("/relation/count/following/:id", middleware.RequireToken(), handling.Wrap("关注列表获取失败", countFollowingsHandler))
	a.GET("/relation/count/followers/:id", middleware.RequireToken(), handling.Wrap("粉丝列表获取失败", countFollowersHandler))
	a.GET("/relation/count/friends/:id", middleware.RequireToken(), handling.Wrap("好友列表获取失败", countFriendsHandler))
	a.POST("/relation/follow/:id", middleware.RequireToken(), handling.Wrap("关注失败", followUserHandler))
	a.DELETE("/relation/follow/:id", middleware.RequireToken(), handling.Wrap("取消关注失败", unfollowUserHandler))
	a.GET("/relation/query/:id", middleware.RequirePermission(permsvc.PermUserRelationRead), handling.Wrap("关注关系获取失败", getFollowStatusHandler))
	i.POST("/relation/follow/:userID/:id", middleware.RequireToken(), handling.Wrap("关注失败", followUserHandler))
	i.DELETE("/relation/follow/:userID/:id", middleware.RequireToken(), handling.Wrap("取消关注失败", unfollowUserHandler))
}
