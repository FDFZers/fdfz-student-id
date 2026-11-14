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

const appIconSlugPrefix = "/student_id/app_icons/"

func appIconSlug(appID int64) string {
	return appIconSlugPrefix + strconv.FormatInt(appID, 10)
}

// setIconHandler 上传应用图标：管理员与应用所有者均可操作。
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
