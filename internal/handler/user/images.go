package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/validation"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

type profileImageKind struct {
	Field          string
	Slug           string
	Item           string
	AdminWritePerm string
	SelfWritePerm  string
	AdminReadPerm  string
	SelfReadPerm   string
}

var (
	avatarImage = profileImageKind{
		Field:          "avatar",
		Slug:           "avatars",
		Item:           "头像",
		AdminWritePerm: "student_id.users.profile.avatar.write",
		SelfWritePerm:  "student_id.user.profile.avatar.write",
		AdminReadPerm:  "student_id.user.profile.avatar.read",
		SelfReadPerm:   "student_id.user.profile.avatar.read.self",
	}
	bannerImage = profileImageKind{
		Field:          "banner",
		Slug:           "banners",
		Item:           "背景图",
		AdminWritePerm: "student_id.users.profile.banner.write",
		SelfWritePerm:  "student_id.user.profile.banner.write",
		AdminReadPerm:  "student_id.user.profile.banner.read",
		SelfReadPerm:   "student_id.user.profile.banner.read.self",
	}
)

func setAvatarHandler(c *gin.Context) { setProfileImageHandler(c, avatarImage) }
func setBannerHandler(c *gin.Context) { setProfileImageHandler(c, bannerImage) }
func getAvatarHandler(c *gin.Context) { serveProfileImage(c, avatarImage) }
func getBannerHandler(c *gin.Context) { serveProfileImage(c, bannerImage) }

func setProfileImageHandler(c *gin.Context, kind profileImageKind) {
	failMsg := kind.Item + "设置失败"

	form, error := c.MultipartForm()
	if error != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", failMsg).Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	target, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails(failMsg).Respond(c)
		return
	}
	targetStr := strconv.FormatInt(target, 10)

	hasAdmin := perm.Contains(claims.Permissions, kind.AdminWritePerm)
	hasSelf := target == claims.UserID && perm.Contains(claims.Permissions, kind.SelfWritePerm)
	if !hasAdmin && !hasSelf {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	fileHeaders := form.File[kind.Field]
	switch {
	case len(fileHeaders) == 0:
		errs.BadRequestError().AppendDetails("请上传"+kind.Item, failMsg).Respond(c)
		return
	case len(fileHeaders) > 1:
		errs.BadRequestError().AppendDetails(kind.Item+"最多上传 1 张", failMsg).Respond(c)
		return
	}
	fileHeader := fileHeaders[0]

	if err := validation.ValidateMIMEType(fileHeader, map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}); err != nil {
		err.AppendDetails(failMsg).Respond(c)
		return
	}

	if err := filestore.UploadFile(fileHeader, &filestore.StoreFileReq{
		Slug:         "/student_id/" + kind.Slug + "/" + targetStr,
		FileName:     targetStr + strings.ToLower(path.Ext(fileHeader.Filename)),
		ShouldUpsert: true,
		AppID:        null.IntFrom(1),
		UserID:       null.IntFrom(claims.UserID),
	}); err != nil {
		err.AppendDetails(failMsg).Respond(c)
		return
	}
}

func serveProfileImage(c *gin.Context, kind profileImageKind) {
	failMsg := kind.Item + "获取失败"
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails(failMsg).Respond(c)
		return
	}

	permKey := kind.AdminReadPerm
	if targetID == claims.UserID {
		permKey = kind.SelfReadPerm
	}
	if !perm.Contains(claims.Permissions, permKey) {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		err.AppendDetails(failMsg).Respond(c)
		return
	}

	slug := "/student_id/" + kind.Slug + "/" + strconv.FormatInt(targetID, 10)
	fileURL, err := filestore.BuildFileUrl(slug)
	if err != nil {
		err.AppendDetails(failMsg).Respond(c)
		return
	}

	c.Redirect(http.StatusFound, fileURL)
}
