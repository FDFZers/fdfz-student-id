package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"strconv"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/user")
	i := internal.Group("/user")

	a.GET("/profile", middleware.RequireToken(), getUserProfileByIDHandler)
	a.GET("/profile/id/:id", middleware.RequireToken(), getUserProfileByIDHandler)
	a.GET("/profile/username/:username", middleware.RequireToken(), getUserProfileByUsernameHandler)

	a.PATCH("/profile", middleware.RequireToken(), updateUserProfileHandler)
	a.PATCH("/profile/id/:id", middleware.RequireToken(), updateUserProfileHandler)

	a.GET("/avatar", middleware.RequireToken(), getAvatarHandler)
	a.GET("/avatar/:id", middleware.RequireToken(), getAvatarHandler)

	a.GET("/banner", middleware.RequireToken(), getBannerHandler)
	a.GET("/banner/:id", middleware.RequireToken(), getBannerHandler)

	a.PUT("/avatar", middleware.RequireToken(), middleware.LimitSize(5<<20), setAvatarHandler)
	a.PUT("/avatar/:id", middleware.RequireToken(), middleware.LimitSize(5<<20), setAvatarHandler)

	a.PUT("/banner", middleware.RequireToken(), middleware.LimitSize(5<<20), setBannerHandler)
	a.PUT("/banner/:id", middleware.RequireToken(), middleware.LimitSize(5<<20), setBannerHandler)

	a.GET("/search/info", middleware.RequireToken(), SearchInfoHandler)
	a.POST("/search/query", middleware.RequireToken(), SearchQueryHandler)

	i.GET("/ban/:id", middleware.RequireToken(), getUserBanHandler)
	i.POST("/ban/:id", middleware.RequireToken(), banUserHandler)
	i.DELETE("/ban/:id", middleware.RequireToken(), unbanUserHandler)
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
