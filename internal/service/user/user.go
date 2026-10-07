package user

import (
	"context"
	"encoding/json"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"strings"
	"time"
)

const (
	UserCacheDuration           = 10 * time.Minute
	UsernameExistsCacheDuration = 1 * time.Minute
)

func UserCacheKey(id int64) string {
	return fmt.Sprintf("student_id:user:info:id:%d", id)
}

func UserIDCacheKey(username string) string {
	return fmt.Sprintf("student_id:user:id_by_username:%s", username)
}

func UsernameExistsCacheKey(username string) string {
	return fmt.Sprintf("student_id:user:username_exists:%s", strings.ToLower(username))
}

// ---------------------------------------------------------------------------
// 创建用户和密码
// ---------------------------------------------------------------------------

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
    SELECT id, $11
    FROM new_user
    RETURNING user_id, updated_at
)
SELECT u.id, u.created_at, u.updated_at, p.updated_at
FROM new_user u
JOIN new_password p ON p.user_id = u.id
`

func CreateUser(ctx context.Context, u *model.User, pwd *model.UserPassword) *errs.Error {
	if taken, err := IsUsernameTaken(ctx, u.Username); err != nil {
		return err.AppendDetails("用户创建失败")
	} else if taken {
		return errs.ConflictError().AppendDetails("用户名已存在", "用户创建失败")
	}
	vis, err := json.Marshal(u.Visibilities)
	if err != nil {
		return errs.InternalError().AppendDetails("序列化错误", "用户创建失败")
	}

	err = db.R.QueryRow(ctx, createUserWithPasswordSQL,
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
	if err != nil {
		return errs.CreatePGError(err, "用户", "Failed to create user").AppendDetails("用户创建失败")
	}

	// TODO: 增加权限

	db.SetRedis(ctx, UserIDCacheKey(u.Username), u.ID, UserCacheDuration)
	db.SetRedis(ctx, UserCacheKey(u.ID), u, UserCacheDuration)
	db.R.Del(ctx, UsernameExistsCacheKey(u.Username))

	return nil
}

// ---------------------------------------------------------------------------
// 获取用户
// ---------------------------------------------------------------------------

const getUserSQL = `
SELECT id, username, type, student_num, real_name, school,
    nickname, signature, bio, visibilities,
    created_at, updated_at, deleted_at
FROM users
WHERE id = $1 AND deleted_at IS NULL
`

const getUsernameSQL = `
SELECT id FROM users
WHERE username = $1 AND deleted_at IS NULL
`

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
			return &u, nil
		},
	)
	if err != nil {
		return nil, err.AppendDetails("用户获取失败")
	}
	return usr, nil
}

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

func UpdateUser(ctx context.Context, u *model.User) *errs.Error {
	vis, err := json.Marshal(u.Visibilities)
	if err != nil {
		return errs.InternalError().AppendDetails("序列化错误", "用户更新失败")
	}

	oldUser, getErr := GetUserByID(ctx, u.ID)
	if getErr != nil {
		return getErr.AppendDetails("用户更新失败")
	}

	if oldUser.Username != u.Username {
		taken, err := IsUsernameTaken(ctx, u.Username)
		if err != nil {
			return err.AppendDetails("用户更新失败")
		} else if taken {
			return errs.ConflictError().AppendDetails("用户名已存在", "用户更新失败")
		}
	}

	err = db.R.QueryRow(ctx, updateUserSQL,
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
	if err != nil {
		return errs.CreatePGError(err, "用户", "Failed to update user").AppendDetails("用户更新失败")
	}

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
const softDeleteUserSQL = `
UPDATE users
SET deleted_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING username
`

func SoftDeleteUser(ctx context.Context, id int64) *errs.Error {
	var username string
	err := db.R.QueryRow(ctx, softDeleteUserSQL, id).Scan(&username)
	if err != nil {
		return errs.CreatePGError(err, "用户", "Failed to delete user").AppendDetails("用户删除失败")
	}

	db.R.Del(ctx, UserCacheKey(id))
	db.R.Del(ctx, UserIDCacheKey(username))

	return nil
}

// ---------------------------------------------------------------------------
// 检查用户名是否存在
// ---------------------------------------------------------------------------

const checkUsernameExistsSQL = `
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE lower(username) = lower($1) AND deleted_at IS NULL
    UNION ALL
    SELECT 1 FROM register_requests
    WHERE lower(username) = lower($1) AND status = 'pending'
)
`

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
