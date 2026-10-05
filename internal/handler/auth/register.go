// Package auth 实现认证相关的 HTTP 处理器。
package auth

import (
	"fdfz-student-id/internal/crypto"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/validation"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

type createRegisterRequestReq struct {
	Username      string         `form:"username"`
	Type          model.UserType `form:"type" binding:"required"`
	StudentNum    string         `form:"student_num"`
	RealName      string         `form:"real_name"`
	School        model.School   `form:"school" binding:"required"`
	Password      string         `form:"password"`
	AltchaPayload string         `form:"altcha_payload"`
}

func createRegisterHandler(c *gin.Context) {
	// 解析请求
	var req createRegisterRequestReq
	if err := c.ShouldBind(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "注册失败").Respond(c)
		return
	}

	if err := captcha.VerifyPayloadStr(req.AltchaPayload); err != nil {
		err.AppendDetails("注册失败").Respond(c)
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "注册失败").Respond(c)
		return
	}

	fileHeaders := form.File["proof_image"]
	switch {
	case len(fileHeaders) == 0:
		errs.BadRequestError().AppendDetails("请上传证明身份的佐证图片", "注册失败").Respond(c)
		return
	case len(fileHeaders) > 1:
		errs.BadRequestError().AppendDetails("佐证图片最多上传 1 张", "注册失败").Respond(c)
		return
	}
	fileHeader := fileHeaders[0]

	var studentNum null.String
	if req.StudentNum != "" {
		studentNum = null.StringFrom(req.StudentNum)
	}

	if req.Type == model.UserTypeStudent {
		if !studentNum.Valid {
			errs.BadRequestError().AppendDetails("学生账号需提供学号", "注册失败").Respond(c)
			return
		}
		if err := validation.ValidateStudentNum(studentNum.String); err != nil {
			err.AppendDetails("注册失败").Respond(c)
			return
		}
	}

	if err := validation.ValidateUsername(req.Username); err != nil {
		err.AppendDetails("注册失败").Respond(c)
		return
	}
	if err := validation.ValidateRealName(req.RealName); err != nil {
		err.AppendDetails("注册失败").Respond(c)
		return
	}
	if err := validation.ValidatePassword(req.Password); err != nil {
		err.AppendDetails("注册失败").Respond(c)
		return
	}
	if err := validation.ValidateMIMEType(fileHeader, map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}); err != nil {
		err.AppendDetails("注册失败").Respond(c)
		return
	}

	// 查询用户名占用信息
	if taken, err := user.IsUsernameTaken(c.Request.Context(), req.Username); err != nil {
		errs.InternalError().AppendDetails("用户名占用信息查询失败", "注册失败").Respond(c)
		return
	} else if taken {
		errs.ConflictError().AppendDetails("用户名已存在", "注册失败").Respond(c)
		return
	}

	// 密码哈希
	pwdHash, err := crypto.HashArgon2ID(req.Password)
	if err != nil {
		errs.InternalError().AppendDetails("密码哈希失败", "注册失败").Respond(c)
		return
	}

	// 创建注册请求
	r := &model.RegisterRequest{
		Username:   req.Username,
		Type:       req.Type,
		StudentNum: studentNum,
		RealName:   req.RealName,
		School:     req.School,
		Password:   pwdHash,
	}

	if err := user.CreateRegisterRequest(c.Request.Context(), r); err != nil {
		err.AppendDetails("注册失败").Respond(c)
		return
	}

	// 上传佐证图片
	if err := filestore.UploadFile(fileHeader, &filestore.StoreFileReq{
		Slug:      "/student_id/proof_images/" + strconv.FormatInt(r.ID, 10),
		FileName:  strconv.FormatInt(r.ID, 10) + strings.ToLower(path.Ext(fileHeader.Filename)),
		IsPrivate: true,
		AppID:     null.IntFrom(1),
	}); err != nil {
		if err := user.DeleteRegisterRequest(c.Request.Context(), r.ID); err != nil {
			err.AppendDetails("注册失败且回退失败，请联系管理员").Respond(c)
			return
		}
		err.AppendDetails("注册失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}
