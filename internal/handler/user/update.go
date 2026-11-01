package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

type updateVisibilitiesReq struct {
	RealName  *model.Visibility `json:"real_name"`
	Followers *model.Visibility `json:"followers"`
	Following *model.Visibility `json:"following"`
}

func (r *updateVisibilitiesReq) empty() bool {
	return r == nil || (r.RealName == nil && r.Followers == nil && r.Following == nil)
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
		(r.Visibilities == nil || r.Visibilities.empty()) &&
		r.Username == nil &&
		r.RealName == nil &&
		r.School == nil &&
		r.StudentNum == nil
}

func updateUserProfileHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}

	var req updateProfileReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if req.empty() {
		return errs.BadRequestError().AppendDetails("未提供需要修改的字段")
	}

	target, err := user.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		return err
	} else if target == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	isSelf := claims.UserID == targetID

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
		{"visibilities", req.Visibilities != nil && !req.Visibilities.empty()},
	}
	for _, f := range selfFields {
		if f.Present && !hasWritePerm(f.Field) {
			return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
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
			return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
		}
	}

	if req.Nickname != nil {
		if *req.Nickname == "" {
			target.Nickname = null.String{}
		} else {
			if err := handling.ValidateNickname(*req.Nickname); err != nil {
				return err
			}
			target.Nickname = null.StringFrom(*req.Nickname)
		}
	}
	if req.Signature != nil {
		if err := handling.ValidateSignature(*req.Signature); err != nil {
			return err
		}
		target.Signature = *req.Signature
	}
	if req.Bio != nil {
		if err := handling.ValidateBio(*req.Bio); err != nil {
			return err
		}
		target.Bio = *req.Bio
	}
	if req.Visibilities != nil {
		for _, field := range []struct {
			Value *model.Visibility
			Dest  *model.Visibility
		}{
			{req.Visibilities.RealName, &target.Visibilities.RealName},
			{req.Visibilities.Followers, &target.Visibilities.Followers},
			{req.Visibilities.Following, &target.Visibilities.Following},
		} {
			if field.Value == nil {
				continue
			}
			if err := handling.ValidateVisibility(*field.Value); err != nil {
				return err
			}
			*field.Dest = *field.Value
		}
	}
	if req.Username != nil && *req.Username != target.Username {
		if err := handling.ValidateUsername(*req.Username); err != nil {
			return err
		}
		target.Username = *req.Username
	}
	if req.RealName != nil && *req.RealName != target.RealName {
		if err := handling.ValidateRealName(*req.RealName); err != nil {
			return err
		}
		target.RealName = *req.RealName
	}
	if req.School != nil {
		if err := handling.ValidateSchool(*req.School); err != nil {
			return err
		}
		target.School = *req.School
	}
	if req.StudentNum != nil {
		if *req.StudentNum == "" {
			target.StudentNum = null.String{}
		} else {
			if err := handling.ValidateStudentNum(*req.StudentNum); err != nil {
				return err
			}
			target.StudentNum = null.StringFrom(*req.StudentNum)
		}
	}

	if target.Type == model.UserTypeStudent {
		if !target.StudentNum.Valid {
			return errs.BadRequestError().AppendDetails("学生账号必须提供学号")
		}
	} else {
		target.StudentNum = null.String{}
	}

	if err := user.UpdateUser(c.Request.Context(), target); err != nil {
		return err
	}

	c.JSON(http.StatusOK, filterProfiles(claims, target)[0])
	return nil
}
