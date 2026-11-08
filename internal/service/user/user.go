// Package user 实现用户域的业务逻辑与数据访问：用户资料、密码/TOTP、邮箱/QQ、关注关系、封禁、
// 注册申请与账号注销。错误 details 只追加具体原因或子步骤失败，端点级失败文案由处理器所在的
// handling.Wrap 统一追加。
package user

import (
	"context"
	"encoding/json"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
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

// rowQuerier 抽象单行查询能力：*pgxpool.Pool 与 pgx.Tx 都满足，使创建用户流程既可在连接池上执行，
// 也可在审核事务内执行，从而让唯一性校验与写入使用同一个事务视图。
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// createUserWithPasswordAt 在指定查询器上创建用户与密码：先在同一查询器上做用户名/学号唯一性校验，
// 再用单条 CTE 原子写入 users 与 user_passwords，回填 ID、时间戳。
// 注意：pwd.Password 必须已由调用方完成哈希；excludeRegisterRequestID 供审核流程排除当前申请自身
// （事务内申请仍是 pending，不排除会被唯一性查询误判为已占用，传 nil 表示不排除）。
func createUserWithPasswordAt(
	ctx context.Context,
	q rowQuerier,
	u *model.User,
	pwd *model.UserPassword,
	excludeRegisterRequestID *uuid.UUID,
) *errs.Error {
	if taken, err := isUsernameTakenAt(ctx, q, u.Username, excludeRegisterRequestID); err != nil {
		return errs.CreatePGError(err, "用户", "Failed to check username").AppendDetails("用户创建失败")
	} else if taken {
		return errs.ConflictError().AppendDetails("用户名已存在", "用户创建失败")
	}
	if u.Type == model.UserTypeStudent {
		if taken, err := isStudentNumTakenAt(ctx, q, u.School, u.StudentNum, 0, excludeRegisterRequestID); err != nil {
			return errs.CreatePGError(err, "学号占用信息", "Failed to check student num").AppendDetails("用户创建失败")
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

	e = q.QueryRow(ctx, createUserWithPasswordSQL,
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
	return nil
}

// CreateUser 创建用户及其密码：先校验用户名/学号占用，再原子写入两张表并刷新缓存。
// 注意：pwd.Password 必须已由调用方完成哈希；学号占用检查同时覆盖待审核的注册申请。
func CreateUser(ctx context.Context, u *model.User, pwd *model.UserPassword) *errs.Error {
	if err := createUserWithPasswordAt(ctx, db.R.Pool, u, pwd, nil); err != nil {
		return err
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

// getUserIncludingDeletedSQL 按 ID 查询用户，包含已软删除用户（资料字段已被清空，仅保留账号标识）。
const getUserIncludingDeletedSQL = `
SELECT id, username, type, student_num, real_name, school,
    nickname, signature, bio, visibilities,
    created_at, updated_at, deleted_at
FROM users
WHERE id = $1
`

// getUsernameSQL 按用户名（大小写不敏感）查询用户 ID，软删除的用户不返回。
const getUsernameSQL = `
SELECT id FROM users
WHERE lower(username) = lower($1) AND deleted_at IS NULL
`

// getUsernameIncludingDeletedSQL 按用户名（大小写不敏感）查询用户 ID，包含已软删除用户。
// 注意：注销后仍可再次注册同名账号，因此可能同时存在活跃与已注销的同名记录；
// 优先返回活跃用户，其次返回最近一条已注销记录，避免资料接口随机命中空壳历史账号。
const getUsernameIncludingDeletedSQL = `
SELECT id FROM users
WHERE lower(username) = lower($1)
ORDER BY (deleted_at IS NOT NULL), id DESC
LIMIT 1
`

// scanUser 从一行用户记录扫描出 model.User，并解析/归一化 visibilities JSON。
// 返回的 error 保留 pgx.ErrNoRows 等原始错误，供调用方按缓存/接口语义分别处理。
func scanUser(row pgx.Row) (*model.User, error) {
	var u model.User
	var vis []byte

	err := row.Scan(
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
}

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
			return scanUser(db.R.QueryRow(ctx, getUserSQL, id))
		},
	)
	if err != nil {
		return nil, err
	}
	return usr, nil
}

// GetUserByIDIncludingDeleted 按 ID 查询用户，不过滤软删除且不走缓存；返回 nil 表示用户不存在。
// 用于资料接口对已注销用户返回最小化的 deleted 标识，而不是 404。
func GetUserByIDIncludingDeleted(
	ctx context.Context,
	id int64,
) (*model.User, *errs.Error) {
	u, err := scanUser(db.R.QueryRow(ctx, getUserIncludingDeletedSQL, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户", "Failed to get user including deleted")
	}
	return u, nil
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

// GetUserByUsernameIncludingDeleted 按用户名查询用户，不过滤软删除且不走缓存；返回 nil 表示用户不存在。
// 同名时优先返回活跃用户（见 getUsernameIncludingDeletedSQL），没有活跃用户时返回最近注销的记录。
func GetUserByUsernameIncludingDeleted(
	ctx context.Context,
	username string,
) (*model.User, *errs.Error) {
	var id int64
	err := db.R.QueryRow(ctx, getUsernameIncludingDeletedSQL, username).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户", "Failed to get user id including deleted")
	}
	return GetUserByIDIncludingDeleted(ctx, id)
}

// ---------------------------------------------------------------------------
// 更新用户
// ---------------------------------------------------------------------------

// updateUserSQL 整体更新用户可编辑字段（不含 type/password），由触发器维护 updated_at。
// 末尾的 updated_at 条件实现乐观锁：仅当记录自读取后未被他人修改时才写库，避免后写覆盖先写。
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
WHERE id = $1 AND deleted_at IS NULL AND updated_at = $10
RETURNING updated_at
`

// userExistsSQL 判断未软删除的用户是否存在，用于乐观锁更新 0 行时区分「并发修改」与「用户已删除」。
const userExistsSQL = `
SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)
`

// UpdateUser 整体更新用户资料：先读取旧记录判断用户名/学号是否变更，再做占用校验并写库，最后失效相关缓存。
// expectedUpdatedAt 是调用方读取用户时的 updated_at 原值，用于乐观锁：记录在此期间被他人修改时返回 409。
func UpdateUser(ctx context.Context, u *model.User, expectedUpdatedAt time.Time) *errs.Error {
	vis, e := json.Marshal(u.Visibilities)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to marshal user visibilities").AppendDetails("序列化错误")
	}

	// 读取旧记录，用于判断用户名/学号是否变化

	oldUser, err := GetUserByID(ctx, u.ID)
	if err != nil {
		return err
	}
	// 用户可能在读取后、写库前被并发软删除，此时按「用户不存在」处理，避免空指针
	if oldUser == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

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
		expectedUpdatedAt,
	).Scan(&u.UpdatedAt)
	if e != nil {
		// 0 行：再查一次用户是否仍存在，区分并发修改（409）与已被删除（404）
		if errors.Is(e, pgx.ErrNoRows) {
			var exists bool
			if qErr := db.R.QueryRow(ctx, userExistsSQL, u.ID).Scan(&exists); qErr != nil {
				return errs.CreatePGError(qErr, "用户", "Failed to check user existence")
			}
			if exists {
				return errs.ConflictError().AppendDetails("资料已被他人修改，请刷新后重试")
			}
			return errs.NotFoundError().AppendDetails("用户不存在")
		}
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
// $2 可排除指定注册申请（审核事务内排除申请自身），传 NULL 表示不排除。
const checkUsernameExistsSQL = `
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE lower(username) = lower($1) AND deleted_at IS NULL
    UNION ALL
    SELECT 1 FROM register_requests
    WHERE lower(username) = lower($1) AND status = 'pending'
      AND ($2::uuid IS NULL OR id <> $2)
)
`

// isUsernameTakenAt 在指定查询器上检查用户名占用（不走缓存），excludeRegisterRequestID 传 nil 表示不排除。
// 审核流程必须在事务内使用本函数：缓存版 IsUsernameTaken 无法与本事务未提交的写入保持一致。
func isUsernameTakenAt(ctx context.Context, q rowQuerier, username string, excludeRegisterRequestID *uuid.UUID) (bool, error) {
	var taken bool
	err := q.QueryRow(ctx, checkUsernameExistsSQL, username, excludeRegisterRequestID).Scan(&taken)
	return taken, err
}

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
			if err := db.R.QueryRow(ctx, checkUsernameExistsSQL, username, nil).Scan(&taken); err != nil {
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
// $4 可排除指定注册申请（审核事务内排除申请自身），传 NULL 表示不排除。
const checkStudentNumExistsSQL = `
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE type = 'student' AND deleted_at IS NULL
      AND school = $1 AND student_num = $2 AND id <> $3
    UNION ALL
    SELECT 1 FROM register_requests
    WHERE type = 'student' AND status = 'pending'
      AND school = $1 AND student_num = $2
      AND ($4::uuid IS NULL OR id <> $4)
)
`

// isStudentNumTakenAt 在指定查询器上检查学号占用（不走缓存），可排除用户自身与正在审核的申请。
func isStudentNumTakenAt(
	ctx context.Context,
	q rowQuerier,
	school model.School,
	studentNum null.String,
	excludeUserID int64,
	excludeRegisterRequestID *uuid.UUID,
) (bool, error) {
	if !studentNum.Valid {
		return false, nil
	}
	var taken bool
	err := q.QueryRow(ctx, checkStudentNumExistsSQL, school, studentNum.String, excludeUserID, excludeRegisterRequestID).Scan(&taken)
	return taken, err
}

// IsStudentNumTaken 检查学号是否已被现存用户或待审核的注册申请占用；studentNum 为空时直接返回 false。
// excludeUserID 用于更新场景排除用户自己；本函数不缓存结果。
func IsStudentNumTaken(
	ctx context.Context,
	school model.School,
	studentNum null.String,
	excludeUserID int64,
) (bool, *errs.Error) {
	taken, err := isStudentNumTakenAt(ctx, db.R.Pool, school, studentNum, excludeUserID, nil)
	if err != nil {
		return false, errs.CreatePGError(err, "学号占用信息", "Failed to check student num")
	}
	return taken, nil
}
