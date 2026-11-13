package app

import (
	"fdfz-student-id/internal/errs"
	appsvc "fdfz-student-id/internal/service/app"
	filestoresvc "fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// appIconSlugPrefix 是应用图标在 filestore 中的固定路径前缀，后接应用 ID。
const appIconSlugPrefix = "/student_id/app_icons/"

// appIconSlug 返回应用图标的 filestore slug；图标是否存在由 filestore 判断。
func appIconSlug(appID int64) string {
	return appIconSlugPrefix + strconv.FormatInt(appID, 10)
}

// setIconHandler 上传应用图标：管理员与应用所有者均可操作。
// 仅接受 JPEG/PNG/WebP，服务端检测类型并决定扩展名，同一应用只保留一张图标（按 slug 覆盖）。
func setIconHandler(c *gin.Context) *errs.Error {
	a, err := managedApp(c, true)
	if err != nil {
		return err
	}

	form, e := c.MultipartForm()
	if e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	fileHeader, mimeType, extension, err := handling.ValidateImageUpload(form.File["icon"], "图标")
	if err != nil {
		return err
	}

	// 路径与应用 ID 绑定，文件名统一由服务端检测结果生成
	appID := strconv.FormatInt(a.ID, 10)
	if err := filestoresvc.UploadFile(fileHeader, &filestoresvc.StoreFileReq{
		Slug:         appIconSlug(a.ID),
		FileName:     appID + extension,
		Description:  "OAuth 应用图标",
		ContentType:  null.StringFrom(mimeType),
		ShouldUpsert: true,
		AppID:        null.IntFrom(a.ID),
	}); err != nil {
		return err
	}

	respondApp(c, a)
	return nil
}

// deleteIconHandler 删除应用图标：直接删除 filestore 中的固定 slug 文件。
// 文件不存在时返回「未设置图标」，与用户头像删除行为一致。
func deleteIconHandler(c *gin.Context) *errs.Error {
	a, err := managedApp(c, true)
	if err != nil {
		return err
	}

	if err := filestoresvc.DeleteFile(appIconSlug(a.ID)); err != nil {
		if err.HTTPCode == http.StatusNotFound {
			return errs.NotFoundError().AppendDetails("未设置图标")
		}
		return err
	}

	respondApp(c, a)
	return nil
}

// getIconHandler 公开读取应用图标：校验应用存在后 302 跳转到 filestore 的固定 slug。
// 该接口不要求登录，供 OAuth 授权页等公开页面展示应用图标；文件不存在时由 filestore 返回 404。
func getIconHandler(c *gin.Context) *errs.Error {
	appID, err := handling.ParseID(c, "appID", "应用")
	if err != nil {
		return err
	}

	a, err := appsvc.GetAppByID(c.Request.Context(), appID)
	if err != nil {
		return err
	}
	if a == nil {
		return errs.NotFoundError().AppendDetails("应用不存在")
	}

	fileURL, err := filestoresvc.BuildFileUrl(appIconSlug(appID))
	if err != nil {
		return err
	}

	c.Redirect(http.StatusFound, fileURL)
	return nil
}
