package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
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

func setAvatarHandler(c *gin.Context) *errs.Error { return setProfileImageHandler(c, avatarImage) }
func setBannerHandler(c *gin.Context) *errs.Error { return setProfileImageHandler(c, bannerImage) }
func getAvatarHandler(c *gin.Context) *errs.Error { return serveProfileImage(c, avatarImage) }
func getBannerHandler(c *gin.Context) *errs.Error { return serveProfileImage(c, bannerImage) }
func deleteAvatarHandler(c *gin.Context) *errs.Error {
	return deleteProfileImageHandler(c, avatarImage)
}
func deleteBannerHandler(c *gin.Context) *errs.Error {
	return deleteProfileImageHandler(c, bannerImage)
}

func setProfileImageHandler(c *gin.Context, kind profileImageKind) *errs.Error {
	form, e := c.MultipartForm()
	if e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	target, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}
	targetStr := strconv.FormatInt(target, 10)

	hasAdmin := perm.Contains(claims.Permissions, kind.AdminWritePerm)
	hasSelf := target == claims.UserID && perm.Contains(claims.Permissions, kind.SelfWritePerm)
	if !hasAdmin && !hasSelf {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	fileHeaders := form.File[kind.Field]
	switch {
	case len(fileHeaders) == 0:
		return errs.BadRequestError().AppendDetails("请上传" + kind.Item)
	case len(fileHeaders) > 1:
		return errs.BadRequestError().AppendDetails(kind.Item + "最多上传 1 张")
	}
	fileHeader := fileHeaders[0]

	if err := handling.ValidateMIMEType(fileHeader, map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}); err != nil {
		return err
	}

	if err := filestore.UploadFile(fileHeader, &filestore.StoreFileReq{
		Slug:         "/student_id/" + kind.Slug + "/" + targetStr,
		FileName:     targetStr + strings.ToLower(path.Ext(fileHeader.Filename)),
		ShouldUpsert: true,
		AppID:        null.IntFrom(1),
		UserID:       null.IntFrom(claims.UserID),
	}); err != nil {
		return err
	}

	return nil
}

func serveProfileImage(c *gin.Context, kind profileImageKind) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}

	permKey := kind.AdminReadPerm
	if targetID == claims.UserID {
		permKey = kind.SelfReadPerm
	}
	if !perm.Contains(claims.Permissions, permKey) {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		return err
	}

	slug := "/student_id/" + kind.Slug + "/" + strconv.FormatInt(targetID, 10)
	fileURL, err := filestore.BuildFileUrl(slug)
	if err != nil {
		return err
	}

	c.Redirect(http.StatusFound, fileURL)
	return nil
}

func deleteProfileImageHandler(c *gin.Context, kind profileImageKind) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	target, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}

	hasAdmin := perm.Contains(claims.Permissions, kind.AdminWritePerm)
	hasSelf := target == claims.UserID && perm.Contains(claims.Permissions, kind.SelfWritePerm)
	if !hasAdmin && !hasSelf {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := EnsureUserExists(c, target); err != nil {
		return err
	}

	slug := "/student_id/" + kind.Slug + "/" + strconv.FormatInt(target, 10)
	if err := filestore.DeleteFile(slug); err != nil {
		if err.HTTPCode == http.StatusNotFound {
			return errs.NotFoundError().AppendDetails("未设置" + kind.Item)
		}
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
