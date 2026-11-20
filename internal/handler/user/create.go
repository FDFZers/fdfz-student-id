package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// adminCreateUserReq 是管理员直接创建账号的请求体。
// 与注册申请不同，管理员创建账号不需要佐证图片与人机验证，密码由管理员设置。
type adminCreateUserReq struct {
	Username   string         `json:"username"`    // 用户名
	Nickname   string         `json:"nickname"`    // 昵称，留空或与用户名相同时不保存
	Type       model.UserType `json:"type"`        // 用户类型
	StudentNum string         `json:"student_num"` // 学号，学生类型必填
	RealName   string         `json:"real_name"`   // 真实姓名
	School     model.School   `json:"school"`      // 学校
	Password   string         `json:"password"`    // 初始密码

	// RequirePasswordReset 是否要求用户下次登录后重设密码，缺省为 true。
	RequirePasswordReset *bool `json:"require_password_reset"`
}

// createUserHandler 管理员直接创建账号：校验字段后写入用户、初始密码与默认用户组。
// 需要 users.create 权限；账号默认标记为需要重设密码，提醒用户尽快更换管理员设置的初始密码。
func createUserHandler(c *gin.Context) *errs.Error {
	var req adminCreateUserReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	// 校验字段格式与身份/学号组合

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
	if err := handling.ValidateRegisterStudentNum(req.Type, req.StudentNum); err != nil {
		return err
	}

	var nickname null.String
	if req.Nickname != "" && req.Nickname != req.Username {
		nickname = null.StringFrom(req.Nickname)
	}

	var studentNum null.String
	if req.StudentNum != "" {
		studentNum = null.StringFrom(req.StudentNum)
	}

	// 哈希初始密码
	pwdHash, e := crypto.HashArgon2ID(req.Password)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to hash initial password").AppendDetails("密码哈希失败")
	}

	requireReset := req.RequirePasswordReset == nil || *req.RequirePasswordReset

	u := &model.User{
		Username:              req.Username,
		Nickname:              nickname,
		Type:                  req.Type,
		StudentNum:            studentNum,
		RealName:              req.RealName,
		School:                req.School,
		PasswordResetRequired: requireReset,
	}
	if err := usersvc.CreateUser(c.Request.Context(), u, &model.UserPassword{Password: pwdHash}); err != nil {
		// 服务层错误已带「用户创建失败」上下文，直接封口避免 Wrap 重复追加。
		return err.Seal()
	}

	claims := handling.MustGetClaims(c)

	slog.Info("User created by admin",
		"user_id", u.ID,
		"username", u.Username,
		"type", u.Type,
		"school", u.School,
		"operator_id", claims.UserID,
		"require_password_reset", requireReset,
	)

	filtered, err := handling.UsersJSON(c.Request.Context(), claims, u)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, filtered[0])
	return nil
}
