// Package user 实现用户域的业务逻辑与数据访问：用户资料、密码/TOTP、邮箱/QQ、关注关系、封禁、
// 注册申请与账号注销。错误 details 只追加具体原因或子步骤失败，端点级失败文案由处理器所在的
// handling.Wrap 统一追加。
package user

import (
	"context"
	"encoding/json"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/guregu/null/v6"
)

// 用户域缓存时长：用户信息与用户名→ID 映射 10 分钟，用户名占用检查 1 分钟（较短以保证注册即时生效）。
const (
	UserCacheDuration           = 10 * time.Minute
	UsernameExistsCacheDuration = 1 * time.Minute
)

// UserCacheKey 返回用户信息缓存的 Redis key（按用户 ID）。
func UserCacheKey(id int64) string {
	return fmt.Sprintf("student_id:user:info:id:%d", id)
}

// UserIDCacheKey 返回「用户名 → 用户 ID」缓存的 Redis key（用户名统一转小写）。
func UserIDCacheKey(username string) string {
	return fmt.Sprintf("student_id:user:id_by_username:%s", strings.ToLower(username))
}

// UsernameExistsCacheKey 返回用户名占用检查缓存的 Redis key（用户名统一转小写）。
func UsernameExistsCacheKey(username string) string {
	return fmt.Sprintf("student_id:user:username_exists:%s", strings.ToLower(username))
}

// ---------------------------------------------------------------------------
// 创建用户和密码
// ---------------------------------------------------------------------------

// createUserWithPasswordSQL 用单条 CTE 原子写入 users 与 user_passwords，避免出现只有用户没有密码的中间状态。
const createUserWithPasswordSQL = `
WITH new_user AS (
    INSERT INTO users (
        username, type, student_num, real_name, school,
        nickname, signature, bio, visibilities
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING id, created_at, updated_at
),
new_password AS (
    INSERT INTO user_passwords (user_id, password)
    SELECT id, $10
    FROM new_user
    RETURNING user_id, updated_at
)
SELECT u.id, u.created_at, u.updated_at, p.updated_at
FROM new_user u
JOIN new_password p ON p.user_id = u.id
`

// CreateUser 创建用户及其密码：先校验用户名/学号占用，再原子写入两张表并刷新缓存。
// 注意：pwd.Password 必须已由调用方完成哈希；学号占用检查同时覆盖待审核的注册申请。
func CreateUser(ctx context.Context, u *model.User, pwd *model.UserPassword) *errs.Error {
	if taken, err := IsUsernameTaken(ctx, u.Username); err != nil {
		return err.AppendDetails("用户创建失败")
	} else if taken {
		return errs.ConflictError().AppendDetails("用户名已存在", "用户创建失败")
	}
	if u.Type == model.UserTypeStudent {
		if taken, err := IsStudentNumTaken(ctx, u.School, u.StudentNum, 0); err != nil {
			return err.AppendDetails("用户创建失败")
		} else if taken {
			return errs.ConflictError().AppendDetails("该学校学号已被注册或正在审核中", "用户创建失败")
		}
	}
	u.Visibilities.Normalize()
	vis, e := json.Marshal(u.Visibilities)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to marshal user visibilities").AppendDetails("序列化错误", "用户创建失败")
	}

	// 单条 SQL 同时创建用户与密码，并回填 ID、时间戳

	e = db.R.QueryRow(ctx, createUserWithPasswordSQL,
		u.Username,
		u.Type,
		u.StudentNum,
		u.RealName,
		u.School,
		u.Nickname,
		u.Signature,
		u.Bio,
		vis,
		pwd.Password,
	).Scan(
		&u.ID,
		&u.CreatedAt,
		&u.UpdatedAt,
		&pwd.UpdatedAt,
	)
	if e != nil {
		return errs.CreatePGError(e, "用户", "Failed to create user").AppendDetails("用户创建失败")
	}

	// TODO: 增加权限

	// 写入用户缓存与用户名映射，并清除用户名占用缓存使新用户名立即生效

	db.SetRedis(ctx, UserIDCacheKey(u.Username), u.ID, UserCacheDuration)
	db.SetRedis(ctx, UserCacheKey(u.ID), u, UserCacheDuration)
	db.R.Del(ctx, UsernameExistsCacheKey(u.Username))

	slog.Info("User created", "user_id", u.ID, "username", u.Username, "type", u.Type, "school", u.School)

	return nil
}

// ---------------------------------------------------------------------------
// 获取用户
// ---------------------------------------------------------------------------

// getUserSQL 按 ID 查询用户，软删除的用户不返回。
const getUserSQL = `
SELECT id, username, type, student_num, real_name, school,
    nickname, signature, bio, visibilities,
    created_at, updated_at, deleted_at
FROM users
WHERE id = $1 AND deleted_at IS NULL
`

// getUsernameSQL 按用户名（大小写不敏感）查询用户 ID，软删除的用户不返回。
const getUsernameSQL = `
SELECT id FROM users
WHERE lower(username) = lower($1) AND deleted_at IS NULL
`

// GetUserByID 按 ID 查询用户：优先读 Redis 缓存，未命中时回源 PostgreSQL 并回填缓存。
// 返回 nil 表示用户不存在或已被软删除；不返回错误对象，调用方需自行判断。
func GetUserByID(
	ctx context.Context,
	id int64,
) (*model.User, *errs.Error) {
	usr, err := db.GetCached(
		ctx,
		"用户",
		UserCacheKey(id),
		UserCacheDuration,
		func() (*model.User, error) {
			var u model.User
			var vis []byte

			err := db.R.QueryRow(ctx, getUserSQL, id).Scan(
				&u.ID,
				&u.Username,
				&u.Type,
				&u.StudentNum,
				&u.RealName,
				&u.School,
				&u.Nickname,
				&u.Signature,
				&u.Bio,
				&vis,
				&u.CreatedAt,
				&u.UpdatedAt,
				&u.DeletedAt,
			)
			if err != nil {
				return nil, err
			}

			if err := json.Unmarshal(vis, &u.Visibilities); err != nil {
				return nil, err
			}
			u.Visibilities.Normalize()
			return &u, nil
		},
	)
	if err != nil {
		return nil, err
	}
	return usr, nil
}

// GetUserByUsername 按用户名查询用户：先解析用户名对应的用户 ID（带缓存），再按 ID 读取用户。
// 用户名不存在时返回 nil，不返回错误。
func GetUserByUsername(
	ctx context.Context,
	username string,
) (*model.User, *errs.Error) {
	id, err := db.GetCached(
		ctx,
		"用户 ID",
		UserIDCacheKey(username),
		UserCacheDuration,
		func() (*int64, error) {
			var id int64
			err := db.R.QueryRow(ctx, getUsernameSQL, username).Scan(&id)
			if err != nil {
				return nil, err
			}
			return &id, nil
		},
	)
	if err != nil {
		return nil, err.AppendDetails("用户 ID 获取失败")
	}
	if id == nil {
		return nil, nil
	}
	return GetUserByID(ctx, *id)
}

// ---------------------------------------------------------------------------
// 更新用户
// ---------------------------------------------------------------------------

// updateUserSQL 整体更新用户可编辑字段（不含 type/password），由触发器维护 updated_at。
const updateUserSQL = `
UPDATE users
SET
    username     = $2,
    student_num  = $3,
    real_name    = $4,
    school       = $5,
    nickname     = $6,
    signature    = $7,
    bio          = $8,
    visibilities = $9
WHERE id = $1 AND deleted_at IS NULL
RETURNING updated_at
`

// UpdateUser 整体更新用户资料：先读取旧记录判断用户名/学号是否变更，再做占用校验并写库，最后失效相关缓存。
// 注意：读取旧记录与写库不在同一事务内，并发更新同一用户时后写覆盖先写。
func UpdateUser(ctx context.Context, u *model.User) *errs.Error {
	vis, e := json.Marshal(u.Visibilities)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to marshal user visibilities").AppendDetails("序列化错误")
	}

	// 读取旧记录，用于判断用户名/学号是否变化

	oldUser, err := GetUserByID(ctx, u.ID)
	if err != nil {
		return err
	}
	// 存疑：oldUser 为 nil（用户被并发软删除）时下面会空指针 panic。

	if !strings.EqualFold(oldUser.Username, u.Username) {
		taken, err := IsUsernameTaken(ctx, u.Username)
		if err != nil {
			return err
		} else if taken {
			return errs.ConflictError().AppendDetails("用户名已存在")
		}
	}

	// 学生修改学校/学号时检查新学号是否已被占用（排除自己）

	if u.Type == model.UserTypeStudent &&
		(oldUser.School != u.School || oldUser.StudentNum != u.StudentNum) {
		taken, err := IsStudentNumTaken(ctx, u.School, u.StudentNum, u.ID)
		if err != nil {
			return err
		} else if taken {
			return errs.ConflictError().AppendDetails("该学校学号已被注册或正在审核中")
		}
	}

	e = db.R.QueryRow(ctx, updateUserSQL,
		u.ID,
		u.Username,
		u.StudentNum,
		u.RealName,
		u.School,
		u.Nickname,
		u.Signature,
		u.Bio,
		vis,
	).Scan(&u.UpdatedAt)
	if e != nil {
		return errs.CreatePGError(e, "用户", "Failed to update user")
	}

	// 用户名变更时清用户名相关缓存；用户信息缓存一律失效

	if oldUser.Username != u.Username {
		db.R.Del(ctx, UserIDCacheKey(oldUser.Username))
		db.R.Del(ctx, UserIDCacheKey(u.Username))
		db.R.Del(ctx, UsernameExistsCacheKey(oldUser.Username))
		db.R.Del(ctx, UsernameExistsCacheKey(u.Username))
	}
	db.R.Del(ctx, UserCacheKey(u.ID))

	return nil
}

// ---------------------------------------------------------------------------
// 软删除用户
// ---------------------------------------------------------------------------

// softDeleteUserSQL 标记用户软删除，返回用户名用于清理缓存。
const softDeleteUserSQL = `
UPDATE users
SET deleted_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING username
`

// SoftDeleteUser 软删除用户并清理用户信息/用户名映射缓存。
// 注意：当前业务代码未调用本函数，账号删除主流程见 FinalizeOverdueAccountDeletion 与 DeleteUser。
func SoftDeleteUser(ctx context.Context, id int64) *errs.Error {
	var username string
	err := db.R.QueryRow(ctx, softDeleteUserSQL, id).Scan(&username)
	if err != nil {
		return errs.CreatePGError(err, "用户", "Failed to delete user")
	}

	db.R.Del(ctx, UserCacheKey(id))
	db.R.Del(ctx, UserIDCacheKey(username))

	return nil
}

// ---------------------------------------------------------------------------
// 检查用户名是否存在
// ---------------------------------------------------------------------------

// checkUsernameExistsSQL 检查用户名是否已被现存用户或待审核的注册申请占用。
const checkUsernameExistsSQL = `
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE lower(username) = lower($1) AND deleted_at IS NULL
    UNION ALL
    SELECT 1 FROM register_requests
    WHERE lower(username) = lower($1) AND status = 'pending'
)
`

// IsUsernameTaken 检查用户名是否已被现存用户或待审核的注册申请占用，结果缓存 1 分钟。
// 注意：来自缓存的结果可能短暂滞后，注册/改名写库后需主动删除 UsernameExistsCacheKey。
func IsUsernameTaken(ctx context.Context, username string) (bool, *errs.Error) {
	exists, err := db.GetCached(
		ctx,
		"用户名占用信息",
		UsernameExistsCacheKey(username),
		UsernameExistsCacheDuration,
		func() (*bool, error) {
			var taken bool
			if err := db.R.QueryRow(ctx, checkUsernameExistsSQL, username).Scan(&taken); err != nil {
				return nil, err
			}
			return &taken, nil
		},
	)
	if err != nil {
		return false, err.AppendDetails("用户名占用信息查询失败")
	}
	if exists == nil { // 不可能为空
		return false, nil
	}
	return *exists, nil
}

// ---------------------------------------------------------------------------
// 检查学号是否已被占用
// ---------------------------------------------------------------------------

// checkStudentNumExistsSQL 检查同校同学号是否已被现存学生或待审核的学生注册申请占用，可排除指定用户自身。
const checkStudentNumExistsSQL = `
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE type = 'student' AND deleted_at IS NULL
      AND school = $1 AND student_num = $2 AND id <> $3
    UNION ALL
    SELECT 1 FROM register_requests
    WHERE type = 'student' AND status = 'pending'
      AND school = $1 AND student_num = $2
)
`

// IsStudentNumTaken 检查学号是否已被现存用户或待审核的注册申请占用；studentNum 为空时直接返回 false。
// excludeUserID 用于更新场景排除用户自己；本函数不缓存结果。
func IsStudentNumTaken(
	ctx context.Context,
	school model.School,
	studentNum null.String,
	excludeUserID int64,
) (bool, *errs.Error) {
	if !studentNum.Valid {
		return false, nil
	}
	var taken bool
	if err := db.R.QueryRow(ctx, checkStudentNumExistsSQL, school, studentNum.String, excludeUserID).Scan(&taken); err != nil {
		return false, errs.CreatePGError(err, "学号占用信息", "Failed to check student num")
	}
	return taken, nil
}
