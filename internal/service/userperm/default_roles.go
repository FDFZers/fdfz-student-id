package userperm

import (
	"context"
	"fmt"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
)

// 内置应用中的系统用户组名称；完整标识为 student_id:<name>。
// 这些名称与 000002 迁移中的种子数据一一对应，修改时需同步迁移。
const (
	RoleNameStudent  = "student"
	RoleNameTeacher  = "teacher"
	RoleNameUser     = "user"
	RoleNameReviewer = "reviewer"
	RoleNameAdmin    = "admin"
)

// defaultRoleNames 返回新用户应自动获得的系统用户组。
func defaultRoleNames(userType model.UserType) ([]string, *errs.Error) {
	switch userType {
	case model.UserTypeStudent:
		return []string{RoleNameStudent, RoleNameUser}, nil
	case model.UserTypeTeacher:
		return []string{RoleNameTeacher, RoleNameUser}, nil
	default:
		return nil, errs.BadRequestError().AppendDetails("用户类型取值错误")
	}
}

// assignDefaultRolesSQL 按应用命名空间与用户组名称写入成员关系；granted_by 为 NULL 表示系统分配。
const assignDefaultRolesSQL = `
INSERT INTO user_roles (user_id, role_id, granted_by)
SELECT $1, r.id, NULL
FROM roles r
JOIN apps a ON a.id = r.app_id
WHERE lower(a.namespace) = lower($2)
  AND a.status = 'active'
  AND a.deleted_at IS NULL
  AND r.name = ANY($3::text[])
ON CONFLICT (user_id, role_id) DO NOTHING
`

// AssignDefaultRoles 为新用户分配系统用户组，必须在创建用户的同一事务内调用。
// 用户组缺失时返回错误而不是静默跳过，避免创建出没有任何权限的账号。
func AssignDefaultRoles(
	ctx context.Context,
	dh db.Handle,
	userID int64,
	userType model.UserType,
) *errs.Error {
	names, err := defaultRoleNames(userType)
	if err != nil {
		return err
	}

	tag, e := dh.Exec(ctx, assignDefaultRolesSQL, userID, appsvc.CoreNamespace, names)
	if e != nil {
		return errs.CreatePGError(e, "用户组", "Failed to assign default roles").AppendDetails("默认用户组分配失败")
	}
	if tag.RowsAffected() != int64(len(names)) {
		return errs.CreateAndLogInternalError(
			fmt.Errorf("default roles not all assigned: user_id=%d, want=%v, affected=%d", userID, names, tag.RowsAffected()),
			"Failed to assign all default roles", "user_id", userID, "roles", names,
		).AppendDetails("系统用户组缺失，请联系管理员")
	}
	return nil
}
