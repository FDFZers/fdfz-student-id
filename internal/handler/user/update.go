package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// updateVisibilitiesReq 资料字段可见性修改请求；字段为空表示不修改。
type updateVisibilitiesReq struct {
	RealName  *model.Visibility `json:"real_name"`
	Followers *model.Visibility `json:"followers"`
	Following *model.Visibility `json:"following"`
}

// empty 判断是否没有任何可见性字段需要修改。
func (r *updateVisibilitiesReq) empty() bool {
	return r == nil || (r.RealName == nil && r.Followers == nil && r.Following == nil)
}

// updateProfileReq 用户资料修改请求；所有字段均为指针，nil 表示不修改。
// 其中 username/real_name/school/student_num 只能由有 users.* 权限的管理方修改，用户本人不能修改。
type updateProfileReq struct {
	Nickname     *string                `json:"nickname"`
	Signature    *string                `json:"signature"`
	Bio          *string                `json:"bio"`
	Visibilities *updateVisibilitiesReq `json:"visibilities"`

	Username   *string       `json:"username"`
	RealName   *string       `json:"real_name"`
	School     *model.School `json:"school"`
	StudentNum *string       `json:"student_num"`
}

// empty 判断请求是否未提供任何需要修改的字段。
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

// updateUserProfileHandler 修改目标用户资料：逐字段校验权限与取值后整体写库，并返回过滤后的资料。
// 需修改自己时使用 user.profile.update.* 权限，修改他人时使用 users.profile.update.* 权限。
// 写库使用 updated_at 乐观锁，资料并发修改时返回 409。
func updateUserProfileHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	// 解析请求并拒绝空更新

	var req updateProfileReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if req.empty() {
		return errs.BadRequestError().AppendDetails("未提供需要修改的字段")
	}

	target, err := usersvc.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		return err
	} else if target == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	expectedUpdatedAt := target.UpdatedAt

	isSelf := claims.UserID == targetID

	// 逐字段校验权限：SelfPerm 为空表示不允许本人修改

	fields := []struct {
		Field     string
		Present   bool
		SelfPerm  string
		OtherPerm string
	}{
		{"username", req.Username != nil, "", permsvc.PermUsersProfileUpdateBasic},
		{"nickname", req.Nickname != nil, permsvc.PermUserProfileUpdateBasic, permsvc.PermUsersProfileUpdateBasic},
		{"signature", req.Signature != nil, permsvc.PermUserProfileUpdateAbout, permsvc.PermUsersProfileUpdateAbout},
		{"bio", req.Bio != nil, permsvc.PermUserProfileUpdateAbout, permsvc.PermUsersProfileUpdateAbout},
		{"real_name", req.RealName != nil, "", permsvc.PermUsersProfileUpdateIdentity},
		{"school", req.School != nil, "", permsvc.PermUsersProfileUpdateIdentity},
		{"student_num", req.StudentNum != nil, "", permsvc.PermUsersProfileUpdateIdentity},
		{"visibilities", req.Visibilities != nil && !req.Visibilities.empty(), permsvc.PermUserProfileUpdateVisibilities, permsvc.PermUsersProfileUpdateVisibilities},
	}
	for _, field := range fields {
		if !field.Present {
			continue
		}
		required := field.OtherPerm
		if isSelf {
			required = field.SelfPerm
		}
		if required == "" || !permsvc.HasPermission(claims, required) {
			return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
		}
	}

	// 应用文本类字段修改，空字符串表示清空可空字段

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

	// 身份类字段改动需要校验；用户名/真名/学校沿用原值时跳过重复校验

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

	// 学生必须保有学号，非学生一律清空学号

	if target.Type == model.UserTypeStudent {
		if !target.StudentNum.Valid {
			return errs.BadRequestError().AppendDetails("学生账号必须提供学号")
		}
	} else {
		target.StudentNum = null.String{}
	}

	// 写库并返回过滤后的最新资料

	if err := usersvc.UpdateUser(c.Request.Context(), target, expectedUpdatedAt); err != nil {
		return err
	}

	filtered, err := handling.UsersJSON(c.Request.Context(), claims, target)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, filtered[0])
	return nil
}
