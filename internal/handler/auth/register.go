// Package auth 实现认证相关的 HTTP 处理器。
package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

type createRegisterRequestReq struct {
	Username      string         `form:"username"`
	Nickname      string         `form:"nickname"`
	Type          model.UserType `form:"type" binding:"required"`
	StudentNum    string         `form:"student_num"`
	RealName      string         `form:"real_name"`
	School        model.School   `form:"school" binding:"required"`
	Password      string         `form:"password"`
	AltchaPayload string         `form:"altcha_payload"`
}

func createRegisterHandler(c *gin.Context) *errs.Error {
	// 解析请求
	var req createRegisterRequestReq
	if err := c.ShouldBind(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	if err := captcha.VerifyPayloadStr(req.AltchaPayload); err != nil {
		return err
	}

	form, err := c.MultipartForm()
	if err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	fileHeaders := form.File["proof_image"]
	switch {
	case len(fileHeaders) == 0:
		return errs.BadRequestError().AppendDetails("请上传证明身份的佐证图片")
	case len(fileHeaders) > 1:
		return errs.BadRequestError().AppendDetails("佐证图片最多上传 1 张")
	}
	fileHeader := fileHeaders[0]

	var studentNum null.String
	if req.StudentNum != "" {
		studentNum = null.StringFrom(req.StudentNum)
	}

	if req.Type == model.UserTypeStudent {
		if !studentNum.Valid {
			return errs.BadRequestError().AppendDetails("学生账号需提供学号")
		}
		if err := handling.ValidateStudentNum(studentNum.String); err != nil {
			return err
		}
	}

	if err := handling.ValidateUsername(req.Username); err != nil {
		return err
	}
	if err := handling.ValidateNickname(req.Nickname); err != nil {
		return err
	}
	if err := handling.ValidateRealName(req.RealName); err != nil {
		return err
	}
	if err := handling.ValidatePassword(req.Password); err != nil {
		return err
	}
	if err := handling.ValidateSchool(req.School); err != nil {
		return err
	}
	if err := handling.ValidateUserType(req.Type); err != nil {
		return err
	}
	if err := handling.ValidateMIMEType(fileHeader, map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
		"image/webp": {},
	}); err != nil {
		return err
	}

	var nickname null.String
	if req.Nickname != "" && req.Nickname != req.Username {
		nickname = null.StringFrom(req.Nickname)
	}

	// 查询用户名占用信息
	if taken, err := user.IsUsernameTaken(c.Request.Context(), req.Username); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to check username availability").AppendDetails("用户名占用信息查询失败")
	} else if taken {
		return errs.ConflictError().AppendDetails("用户名已存在")
	}

	// 密码哈希
	pwdHash, err := crypto.HashArgon2ID(req.Password)
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to hash password").AppendDetails("密码哈希失败")
	}

	// 创建注册请求
	r := &model.RegisterRequest{
		Username:   req.Username,
		Nickname:   nickname,
		Type:       req.Type,
		StudentNum: studentNum,
		RealName:   req.RealName,
		School:     req.School,
		Password:   pwdHash,
	}

	if err := user.CreateRegisterRequest(c.Request.Context(), r); err != nil {
		return err
	}

	// 上传佐证图片
	if err := filestore.UploadFile(fileHeader, &filestore.StoreFileReq{
		Slug:     "/student_id/proof_images/" + r.ID.String(),
		FileName: r.ID.String() + strings.ToLower(path.Ext(fileHeader.Filename)),
		AppID:    null.IntFrom(1),
	}); err != nil {
		if deleteErr := user.DeleteRegisterRequest(c.Request.Context(), r.ID); deleteErr != nil {
			return deleteErr.AppendDetails("注册失败且回退失败，请联系管理员").Seal()
		}
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"id": r.ID,
	})
	return nil
}
