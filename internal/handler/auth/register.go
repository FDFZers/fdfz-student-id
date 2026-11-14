package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	captchasvc "fdfz-student-id/internal/service/captcha"
	filestoresvc "fdfz-student-id/internal/service/filestore"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// createRegisterRequestReq 是注册申请的请求体（multipart 表单，包含佐证图片）。
type createRegisterRequestReq struct {
	Username      string         `form:"username"`                  // 用户名
	Nickname      string         `form:"nickname"`                  // 昵称，留空或与用户名相同时不保存
	Type          model.UserType `form:"type" binding:"required"`   // 用户类型
	StudentNum    string         `form:"student_num"`               // 学号，学生类型必填
	RealName      string         `form:"real_name"`                 // 真实姓名
	School        model.School   `form:"school" binding:"required"` // 学校
	Password      string         `form:"password"`                  // 密码
	AltchaPayload string         `form:"altcha_payload"`            // Altcha 人机验证载荷
}

// createRegisterHandler 创建注册申请并上传佐证图片；注册申请需管理员审核通过后才创建用户。
// 注意：先创建注册申请再上传图片，图片上传失败时会回滚删除申请记录。
func createRegisterHandler(c *gin.Context) *errs.Error {
	// 解析请求
	var req createRegisterRequestReq
	if e := c.ShouldBind(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	if err := captchasvc.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

	// 单 IP 每小时注册请求配额：抬高批量探测用户名/学号是否存在的成本。
	if err := authsvc.TryAcquireRegisterIPQuota(c.Request.Context(), c.ClientIP()); err != nil {
		return err
	}

	form, e := c.MultipartForm()
	if e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	fileHeader, mimeType, extension, err := handling.ValidateImageUpload(form.File["proof_image"], "佐证图片")
	if err != nil {
		return err
	}

	if err := handling.ValidateRegisterStudentNum(req.Type, req.StudentNum); err != nil {
		return err
	}

	var studentNum null.String
	if req.StudentNum != "" {
		studentNum = null.StringFrom(req.StudentNum)
	}

	if err := handling.ValidateUsername(req.Username); err != nil {
		return err
	}
	if req.Nickname != "" && req.Nickname != req.Username {
		if err := handling.ValidateNickname(req.Nickname); err != nil {
			return err
		}
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
	var nickname null.String
	if req.Nickname != "" && req.Nickname != req.Username {
		nickname = null.StringFrom(req.Nickname)
	}

	// 注意：用户名冲突与学号冲突统一使用同一句模糊提示，避免被用来探测用户名/学号是否被占用。
	if taken, err := usersvc.IsUsernameTaken(c.Request.Context(), req.Username); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to check username availability").AppendDetails("用户名占用信息查询失败")
	} else if taken {
		return errs.ConflictError().AppendDetails("用户名或学号不可用，请更换后重试")
	}

	// 密码哈希
	pwdHash, e := crypto.HashArgon2ID(req.Password)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to hash password").AppendDetails("密码哈希失败")
	}

	// 创建注册申请
	r := &model.RegisterRequest{
		Username:   req.Username,
		Nickname:   nickname,
		Type:       req.Type,
		StudentNum: studentNum,
		RealName:   req.RealName,
		School:     req.School,
		Password:   pwdHash,
	}

	if err := usersvc.CreateRegisterRequest(c.Request.Context(), r); err != nil {
		return err
	}

	// 上传佐证图片，失败时回滚删除注册申请
	if err := filestoresvc.UploadFile(fileHeader, &filestoresvc.StoreFileReq{
		Slug:        "/student_id/proof_images/" + r.ID.String(),
		FileName:    r.ID.String() + extension,
		ContentType: null.StringFrom(mimeType),
		AppID:       null.IntFrom(1),
	}); err != nil {
		if err := usersvc.DeleteRegisterRequest(c.Request.Context(), r.ID); err != nil {
			return err.AppendDetails("注册失败且回退失败，请联系管理员").Seal()
		}
		return err
	}

	slog.Info("Register request created", "register_id", r.ID, "username", r.Username, "type", req.Type, "school", req.School)

	c.JSON(http.StatusOK, gin.H{
		"id": r.ID,
	})
	return nil
}
