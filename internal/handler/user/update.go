package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/validation"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

type updateVisibilitiesReq struct {
	RealName *model.Visibility `json:"real_name"`
}

type updateProfileReq struct {
	Nickname     *string                `json:"nickname"`
	Signature    *string                `json:"signature"`
	Bio          *string                `json:"bio"`
	Visibilities *updateVisibilitiesReq `json:"visibilities"`

	// 以下字段仅允许管理员修改
	Username   *string       `json:"username"`
	RealName   *string       `json:"real_name"`
	School     *model.School `json:"school"`
	StudentNum *string       `json:"student_num"`
}

func (r *updateProfileReq) empty() bool {
	return r.Nickname == nil &&
		r.Signature == nil &&
		r.Bio == nil &&
		(r.Visibilities == nil || r.Visibilities.RealName == nil) &&
		r.Username == nil &&
		r.RealName == nil &&
		r.School == nil &&
		r.StudentNum == nil
}

func updateUserProfileHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails("用户信息修改失败").Respond(c)
		return
	}

	var req updateProfileReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "用户信息修改失败").Respond(c)
		return
	}
	if req.empty() {
		errs.BadRequestError().AppendDetails("未提供需要修改的字段", "用户信息修改失败").Respond(c)
		return
	}

	target, err := user.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		err.AppendDetails("用户信息修改失败").Respond(c)
		return
	} else if target == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "用户信息修改失败").Respond(c)
		return
	}

	isSelf := claims.UserID == targetID

	permissionDenied := func() {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
	}
	hasWritePerm := func(field string) bool {
		if isSelf {
			return perm.Contains(claims.Permissions, "student_id.user.profile."+field+".write")
		}
		return perm.Contains(claims.Permissions, "student_id.users.profile."+field+".write")
	}

	// 自身可修改的字段
	selfFields := []struct {
		Field   string
		Present bool
	}{
		{"nickname", req.Nickname != nil},
		{"signature", req.Signature != nil},
		{"bio", req.Bio != nil},
		{"visibilities", req.Visibilities != nil && req.Visibilities.RealName != nil},
	}
	for _, f := range selfFields {
		if f.Present && !hasWritePerm(f.Field) {
			permissionDenied()
			return
		}
	}

	// 仅管理员可修改的字段
	adminFields := []struct {
		Field   string
		Present bool
	}{
		{"username", req.Username != nil},
		{"real_name", req.RealName != nil},
		{"school", req.School != nil},
		{"student_num", req.StudentNum != nil},
	}
	for _, f := range adminFields {
		if !f.Present {
			continue
		}
		if isSelf || !perm.Contains(claims.Permissions, "student_id.users.profile."+f.Field+".write") {
			permissionDenied()
			return
		}
	}

	respondErr := func(err *errs.Error) {
		err.AppendDetails("用户信息修改失败").Respond(c)
	}

	if req.Nickname != nil {
		if *req.Nickname == "" {
			target.Nickname = null.String{}
		} else {
			if err := validation.ValidateNickname(*req.Nickname); err != nil {
				respondErr(err)
				return
			}
			target.Nickname = null.StringFrom(*req.Nickname)
		}
	}
	if req.Signature != nil {
		if err := validation.ValidateSignature(*req.Signature); err != nil {
			respondErr(err)
			return
		}
		target.Signature = *req.Signature
	}
	if req.Bio != nil {
		if err := validation.ValidateBio(*req.Bio); err != nil {
			respondErr(err)
			return
		}
		target.Bio = *req.Bio
	}
	if req.Visibilities != nil && req.Visibilities.RealName != nil {
		if err := validation.ValidateVisibility(*req.Visibilities.RealName); err != nil {
			respondErr(err)
			return
		}
		target.Visibilities.RealName = *req.Visibilities.RealName
	}
	if req.Username != nil && *req.Username != target.Username {
		if err := validation.ValidateUsername(*req.Username); err != nil {
			respondErr(err)
			return
		}
		target.Username = *req.Username
	}
	if req.RealName != nil && *req.RealName != target.RealName {
		if err := validation.ValidateRealName(*req.RealName); err != nil {
			respondErr(err)
			return
		}
		target.RealName = *req.RealName
	}
	if req.School != nil {
		if err := validation.ValidateSchool(*req.School); err != nil {
			respondErr(err)
			return
		}
		target.School = *req.School
	}
	if req.StudentNum != nil {
		if *req.StudentNum == "" {
			target.StudentNum = null.String{}
		} else {
			if err := validation.ValidateStudentNum(*req.StudentNum); err != nil {
				respondErr(err)
				return
			}
			target.StudentNum = null.StringFrom(*req.StudentNum)
		}
	}

	if target.Type == model.UserTypeStudent {
		if !target.StudentNum.Valid {
			errs.BadRequestError().AppendDetails("学生账号必须提供学号", "用户信息修改失败").Respond(c)
			return
		}
	} else {
		target.StudentNum = null.String{}
	}

	if err := user.UpdateUser(c.Request.Context(), target); err != nil {
		err.AppendDetails("用户信息修改失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, filterProfiles(claims, target)[0])
}
