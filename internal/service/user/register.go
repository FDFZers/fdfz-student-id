package user

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

const (
	RegisterRequestCacheDuration = 5 * time.Minute
)

func RegisterRequestCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:register_request:id:%s", id)
}

// ---------------------------------------------------------------------------
// 创建注册请求
// ---------------------------------------------------------------------------

const createRegisterRequestSQL = `
INSERT INTO register_requests (
    username, nickname, type, student_num, real_name, school, password
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at, status,
    created_user_id, reviewer_user_id, review_comment, reviewed_at
`

func CreateRegisterRequest(ctx context.Context, r *model.RegisterRequest) *errs.Error {
	if taken, err := IsUsernameTaken(ctx, r.Username); err != nil {
		return err.AppendDetails("注册请求创建失败")
	} else if taken {
		return errs.ConflictError().AppendDetails("用户名已存在", "注册请求创建失败")
	}

	if r.Type == model.UserTypeStudent {
		if taken, err := IsStudentNumTaken(ctx, r.School, r.StudentNum, 0); err != nil {
			return err.AppendDetails("注册请求创建失败")
		} else if taken {
			return errs.ConflictError().AppendDetails("该学校的学号已存在", "注册请求创建失败")
		}
	}

	err := db.R.QueryRow(ctx, createRegisterRequestSQL,
		r.Username,
		r.Nickname,
		r.Type,
		r.StudentNum,
		r.RealName,
		r.School,
		r.Password,
	).Scan(
		&r.ID,
		&r.CreatedAt,
		&r.Status,
		&r.CreatedUserID,
		&r.ReviewerUserID,
		&r.ReviewComment,
		&r.ReviewedAt,
	)
	if err != nil {
		return errs.CreatePGError(err, "注册请求", "Failed to create register request").
			AppendDetails("注册请求创建失败")
	}

	db.R.Del(ctx, UsernameExistsCacheKey(r.Username))
	db.SetRedis(ctx, RegisterRequestCacheKey(r.ID), r, RegisterRequestCacheDuration)

	return nil
}

// ---------------------------------------------------------------------------
// 获取注册请求
// ---------------------------------------------------------------------------

const getRegisterRequestSQL = `
SELECT id, username, nickname, type, student_num, real_name, school, password,
    created_at, status, created_user_id, reviewer_user_id, review_comment, reviewed_at
FROM register_requests
WHERE id = $1
`

func GetRegisterRequestByID(
	ctx context.Context,
	id uuid.UUID,
) (*model.RegisterRequest, *errs.Error) {
	r, err := db.GetCached(
		ctx,
		"注册请求",
		RegisterRequestCacheKey(id),
		RegisterRequestCacheDuration,
		func() (*model.RegisterRequest, error) {
			var req model.RegisterRequest
			err := db.R.QueryRow(ctx, getRegisterRequestSQL, id).Scan(
				&req.ID,
				&req.Username,
				&req.Nickname,
				&req.Type,
				&req.StudentNum,
				&req.RealName,
				&req.School,
				&req.Password,
				&req.CreatedAt,
				&req.Status,
				&req.CreatedUserID,
				&req.ReviewerUserID,
				&req.ReviewComment,
				&req.ReviewedAt,
			)
			if err != nil {
				return nil, err
			}
			return &req, nil
		},
	)
	if err != nil {
		return nil, err.AppendDetails("注册请求获取失败")
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// 审核注册请求
// ---------------------------------------------------------------------------

const reviewRegisterRequestSQL = `
UPDATE register_requests
SET status = $2, reviewer_user_id = $3, review_comment = $4, reviewed_at = now()
WHERE id = $1 AND status = 'pending'
RETURNING username, reviewed_at
`

const rollbackReviewSQL = `
UPDATE register_requests
SET status = 'pending',
    created_user_id = NULL,
    reviewer_user_id = NULL,
    reviewed_at = NULL
WHERE id = $1 AND status = 'approved'
`

const setRegisterRequestCreatedUserSQL = `
UPDATE register_requests
SET created_user_id = $2
WHERE id = $1 AND status = 'approved'
`

func ReviewRegisterRequest(
	ctx context.Context,
	id uuid.UUID,
	status model.RegisterRequestStatus,
	reviewComment string,
	reviewerID int64,
) *errs.Error {
	var username string
	var reviewedAt time.Time

	if status == model.RegisterRequestStatusPending {
		return errs.BadRequestError().AppendDetails("不能将注册请求标记为待审核", "注册请求审核失败")
	}

	err := db.R.QueryRow(ctx, reviewRegisterRequestSQL, id, status, reviewerID, reviewComment).Scan(&username, &reviewedAt)
	if err != nil {
		return errs.CreatePGError(err, "注册请求", "Failed to review register request").AppendDetails("注册请求审核失败")
	}

	db.R.Del(ctx, RegisterRequestCacheKey(id))
	db.R.Del(ctx, UsernameExistsCacheKey(username))

	if status != model.RegisterRequestStatusApproved {
		return nil
	}

	// 创建用户
	rollback := func(error *errs.Error) *errs.Error {
		if _, err := db.R.Exec(ctx, rollbackReviewSQL, id); err != nil {
			details := errs.CreatePGError(err, "注册请求", "Failed to rollback review").Info.Details
			return error.AppendDetails("注册请求通过失败且回退失败，请联系管理员").AppendDetails(details...)
		}
		return error.AppendDetails("注册请求通过失败")
	}

	req, getErr := GetRegisterRequestByID(ctx, id)
	if getErr != nil {
		return rollback(getErr)
	}
	u := &model.User{
		Username:   req.Username,
		Nickname:   req.Nickname,
		Type:       req.Type,
		StudentNum: req.StudentNum,
		RealName:   req.RealName,
		School:     req.School,
	}
	pwd := &model.UserPassword{
		Password: req.Password,
	}
	if createErr := CreateUser(ctx, u, pwd); createErr != nil {
		return rollback(createErr)
	}

	if _, err := db.R.Exec(ctx, setRegisterRequestCreatedUserSQL, id, u.ID); err != nil {
		slog.Error("Failed to set created user for register request", "error", err, "register_id", id, "user_id", u.ID)
	}

	return nil
}

// ---------------------------------------------------------------------------
// 删除注册请求
// ---------------------------------------------------------------------------

const deleteRegisterRequestSQL = `
DELETE FROM register_requests
WHERE id = $1
RETURNING username
`

func DeleteRegisterRequest(ctx context.Context, id uuid.UUID) *errs.Error {
	var username string
	err := db.R.QueryRow(ctx, deleteRegisterRequestSQL, id).Scan(&username)
	if err != nil {
		return errs.CreatePGError(err, "注册请求", "Failed to delete register request").AppendDetails("注册请求删除失败")
	}

	db.R.Del(ctx, RegisterRequestCacheKey(id))
	db.R.Del(ctx, UsernameExistsCacheKey(username))

	return nil
}
