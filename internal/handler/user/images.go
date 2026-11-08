package user

import (
	"fdfz-student-id/internal/errs"
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

// profileImageKind 描述一种资料图片（头像/背景图）在表单、filestore 路径与错误文案中的命名。
type profileImageKind struct {
	Field string // multipart 上传表单字段名
	Slug  string // filestore 路径中的类型段（avatars/banners）
	Item  string // 面向用户的中文名词
}

// 资料图片的两种类型配置。
var (
	avatarImage = profileImageKind{
		Field: "avatar",
		Slug:  "avatars",
		Item:  "头像",
	}
	bannerImage = profileImageKind{
		Field: "banner",
		Slug:  "banners",
		Item:  "背景图",
	}
)

// setAvatarHandler 设置头像，转交 setProfileImageHandler 处理。
func setAvatarHandler(c *gin.Context) *errs.Error { return setProfileImageHandler(c, avatarImage) }

// setBannerHandler 设置背景图，转交 setProfileImageHandler 处理。
func setBannerHandler(c *gin.Context) *errs.Error { return setProfileImageHandler(c, bannerImage) }

// getAvatarHandler 获取头像，转交 serveProfileImage 重定向到 filestore。
func getAvatarHandler(c *gin.Context) *errs.Error { return serveProfileImage(c, avatarImage) }

// getBannerHandler 获取背景图，转交 serveProfileImage 重定向到 filestore。
func getBannerHandler(c *gin.Context) *errs.Error { return serveProfileImage(c, bannerImage) }

// deleteAvatarHandler 删除头像，转交 deleteProfileImageHandler 处理。
func deleteAvatarHandler(c *gin.Context) *errs.Error {
	return deleteProfileImageHandler(c, avatarImage)
}

// deleteBannerHandler 删除背景图，转交 deleteProfileImageHandler 处理。
func deleteBannerHandler(c *gin.Context) *errs.Error {
	return deleteProfileImageHandler(c, bannerImage)
}

// setProfileImageHandler 上传并保存资料图片：校验权限、表单字段、图片 MIME 类型后写入 filestore。
// 设置自己需要 user.profile.update.basic，设置他人需要 users.profile.update.basic；同一用户仅保留一张，按 upsert 覆盖。
func setProfileImageHandler(c *gin.Context, kind profileImageKind) *errs.Error {
	form, e := c.MultipartForm()
	if e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}
	targetStr := strconv.FormatInt(targetID, 10)

	// 按「设置自己」与「设置他人」区分所需权限

	var allowed bool
	if targetID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserProfileUpdateBasic)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersProfileUpdateBasic)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	fileHeaders := form.File[kind.Field]
	switch {
	case len(fileHeaders) == 0:
		return errs.BadRequestError().AppendDetails("未提供" + kind.Item)
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

	// 上传到 filestore：路径固定为 /student_id/{avatars|banners}/{userID}，同路径覆盖

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

// serveProfileImage 获取资料图片：校验权限与目标用户存在性后，302 重定向到带签名的 filestore 地址。
// 注意：这里不检查文件是否真实存在，文件缺失时由 filestore 返回 404。
func serveProfileImage(c *gin.Context, kind profileImageKind) *errs.Error {
	claims := handling.MustGetClaims(c)

	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	var allowed bool
	if targetID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserProfileReadBasic)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersProfileReadBasic)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	// 构建带下载令牌的 filestore 地址并重定向

	slug := "/student_id/" + kind.Slug + "/" + strconv.FormatInt(targetID, 10)
	fileURL, err := filestore.BuildFileUrl(slug)
	if err != nil {
		return err
	}

	c.Redirect(http.StatusFound, fileURL)
	return nil
}

// deleteProfileImageHandler 删除资料图片：校验权限与目标用户存在性后调用 filestore 删除固定路径的文件。
// 未设置过图片时 filestore 返回 404，这里转换为「未设置头像/未设置背景图」。
func deleteProfileImageHandler(c *gin.Context, kind profileImageKind) *errs.Error {
	claims := handling.MustGetClaims(c)

	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	var allowed bool
	if targetID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserProfileUpdateBasic)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersProfileUpdateBasic)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	// 删除 filestore 中的固定路径文件；文件不存在视为「未设置」

	slug := "/student_id/" + kind.Slug + "/" + strconv.FormatInt(targetID, 10)
	if err := filestore.DeleteFile(slug); err != nil {
		if err.HTTPCode == http.StatusNotFound {
			return errs.NotFoundError().AppendDetails("未设置" + kind.Item)
		}
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
