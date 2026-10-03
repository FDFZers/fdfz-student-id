package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/perm"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/validation"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

func setAvatarHandler(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "头像设置失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetStr := c.Param("id")
	var target int64
	if targetStr != "" {
		target, err = strconv.ParseInt(targetStr, 10, 64)
		if err != nil {
			errs.BadRequestError().AppendDetails("无效的用户 ID", "头像设置失败").Respond(c)
			return
		}
	} else {
		target = claims.UserID
	}
	targetStr = strconv.FormatInt(target, 10)

	hasPerm := perm.Contains(claims.Permissions, "student_id.users.profile.avatar.write")
	hasSelfPerm := perm.Contains(claims.Permissions, "student_id.user.profile.avatar.write")
	if target != claims.UserID {
		if !hasPerm {
			errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
			return
		}
	} else {
		if !hasPerm && !hasSelfPerm {
			errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
			return
		}
	}

	fileHeaders := form.File["avatar"]
	switch {
	case len(fileHeaders) == 0:
		errs.BadRequestError().AppendDetails("请上传头像", "头像设置失败").Respond(c)
		return
	case len(fileHeaders) > 1:
		errs.BadRequestError().AppendDetails("头像最多上传 1 张", "头像设置失败").Respond(c)
		return
	}
	fileHeader := fileHeaders[0]

	if err := validation.ValidateMIMEType(fileHeader, map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}); err != nil {
		err.AppendDetails("头像设置失败").Respond(c)
		return
	}

	if err := filestore.UploadFile(fileHeader, &model.StoreFileReq{
		Slug:     "/student_id/avatars/" + targetStr,
		FileName: targetStr + strings.ToLower(path.Ext(fileHeader.Filename)),
		AppID:    null.IntFrom(1),
		UserID:   null.IntFrom(claims.UserID),
	}); err != nil {
		err.AppendDetails("头像设置失败").Respond(c)
		return
	}
}

func setBannerHandler(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "背景图设置失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetStr := c.Param("id")
	var target int64
	if targetStr != "" {
		target, err = strconv.ParseInt(targetStr, 10, 64)
		if err != nil {
			errs.BadRequestError().AppendDetails("无效的用户 ID", "背景图设置失败").Respond(c)
			return
		}
	} else {
		target = claims.UserID
	}
	targetStr = strconv.FormatInt(target, 10)

	hasPerm := perm.Contains(claims.Permissions, "student_id.users.profile.banner.write")
	hasSelfPerm := perm.Contains(claims.Permissions, "student_id.user.profile.banner.write")
	if target != claims.UserID {
		if !hasPerm {
			errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
			return
		}
	} else {
		if !hasPerm && !hasSelfPerm {
			errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
			return
		}
	}

	fileHeaders := form.File["banner"]
	switch {
	case len(fileHeaders) == 0:
		errs.BadRequestError().AppendDetails("请上传背景图", "背景图设置失败").Respond(c)
		return
	case len(fileHeaders) > 1:
		errs.BadRequestError().AppendDetails("背景图最多上传 1 张", "背景图设置失败").Respond(c)
		return
	}
	fileHeader := fileHeaders[0]

	if err := validation.ValidateMIMEType(fileHeader, map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}); err != nil {
		err.AppendDetails("背景图设置失败").Respond(c)
		return
	}

	if err := filestore.UploadFile(fileHeader, &model.StoreFileReq{
		Slug:     "/student_id/banners/" + targetStr,
		FileName: targetStr + strings.ToLower(path.Ext(fileHeader.Filename)),
		AppID:    null.IntFrom(1),
		UserID:   null.IntFrom(claims.UserID),
	}); err != nil {
		err.AppendDetails("背景图设置失败").Respond(c)
		return
	}
}
