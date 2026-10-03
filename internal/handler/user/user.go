package user

import (
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/perm"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api *gin.RouterGroup) {
	group := api.Group("/user")
	group.GET("/profile/username/:username", middleware.ParseToken(), middleware.RequireToken(), getUserProfileByUsernameHandler)
	group.GET("/profile/id/:id", middleware.ParseToken(), middleware.RequireToken(), getUserProfileByIDHandler)
	group.GET("/ban/:id", middleware.ParseToken(), middleware.RequireToken(), getUserBanHandler)
	group.PUT("/avatar", middleware.ParseToken(), middleware.RequireToken(), middleware.LimitSize(5<<20), setAvatarHandler)
	group.PUT("/banner", middleware.ParseToken(), middleware.RequireToken(), middleware.LimitSize(5<<20), setBannerHandler)
	group.GET("/search/info", middleware.ParseToken(), middleware.RequireToken(), SearchInfoHandler)
	group.POST("/search/query", middleware.ParseToken(), middleware.RequireToken(), SearchQueryHandler)
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
