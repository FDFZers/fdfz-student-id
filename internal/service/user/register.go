package user

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// 创建注册请求
// ---------------------------------------------------------------------------

// createRegisterRequestSQL 插入一条待审核的注册申请，返回数据库生成的 ID、状态与审核字段默认值。
const createRegisterRequestSQL = `
INSERT INTO register_requests (
    username, nickname, type, student_num, real_name, school, password
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at, status,
    created_user_id, reviewer_user_id, review_comment, reviewed_at
`

// CreateRegisterRequest 要求 r.Password 已哈希。
// 用户名/学号冲突统一返回模糊文案，防止账号枚举；并发撞唯一索引时同样如此。
func CreateRegisterRequest(ctx context.Context, r *model.RegisterRequest) *errs.Error {
	// 校验用户名与学号是否已被占用（含待审核申请）

	if taken, err := IsUsernameTaken(ctx, r.Username); err != nil {
		return err
	} else if taken {
		// 与学号冲突使用同一句模糊文案
		return errs.ConflictError().AppendDetails("用户名或学号不可用，请更换后重试")
	}

	if r.Type == model.UserTypeStudent {
		if taken, err := IsStudentNumTaken(ctx, r.School, r.StudentNum, 0); err != nil {
			return err
		} else if taken {
			return errs.ConflictError().AppendDetails("用户名或学号不可用，请更换后重试")
		}
	}

	e := db.R.QueryRow(ctx, createRegisterRequestSQL,
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
	if e != nil {
		err := errs.CreatePGError(e, "注册请求", "Failed to create register request")
		if err.HTTPCode == http.StatusConflict {
			return errs.ConflictError().AppendDetails("用户名或学号不可用，请更换后重试")
		}
		return err
	}

	db.R.Del(ctx, UsernameExistsCacheKey(r.Username))

	return nil
}

// ---------------------------------------------------------------------------
// 获取注册请求
// ---------------------------------------------------------------------------

// getRegisterRequestSQL 按 ID 查询注册申请（含密码哈希，仅供服务层内部使用）。
const getRegisterRequestSQL = `
SELECT id, username, nickname, type, student_num, real_name, school, password,
    created_at, status, created_user_id, reviewer_user_id, review_comment, reviewed_at
FROM register_requests
WHERE id = $1
`

// GetRegisterRequestByID 直接读 PostgreSQL：审核状态在事务内变化，缓存会引入旧快照竞态。
// 返回 nil 表示申请不存在，不返回错误。
func GetRegisterRequestByID(
	ctx context.Context,
	id uuid.UUID,
) (*model.RegisterRequest, *errs.Error) {
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
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "注册请求", "Failed to get register request")
	}
	return &req, nil
}

// ---------------------------------------------------------------------------
// 审核注册请求
// ---------------------------------------------------------------------------

// lockRegisterRequestSQL 在审核事务内按主键锁定并读取申请；FOR UPDATE 保证同一申请不会被并发审核两次。
const lockRegisterRequestSQL = `
SELECT id, username, password, type, student_num, real_name, school, nickname, status
FROM register_requests
WHERE id = $1
FOR UPDATE
`

const rejectRegisterRequestSQL = `
UPDATE register_requests
SET status = $2, reviewer_user_id = $3, review_comment = $4, reviewed_at = now()
WHERE id = $1
`

const approveRegisterRequestSQL = `
UPDATE register_requests
SET status = 'approved', created_user_id = $2, reviewer_user_id = $3, review_comment = $4, reviewed_at = now()
WHERE id = $1
`

// ReviewRegisterRequest 在单个事务内完成状态更新与创建用户，任一环节失败整体回滚。
// 并发审核同一申请时，后到的事务读到非 pending 状态并返回 409。
func ReviewRegisterRequest(
	ctx context.Context,
	id uuid.UUID,
	status model.RegisterRequestStatus,
	reviewComment string,
	reviewerID int64,
) *errs.Error {
	if !status.IsValid() || status == model.RegisterRequestStatusPending {
		return errs.BadRequestError().AppendDetails("审核状态取值错误")
	}

	tx, txErr := db.R.Begin(ctx)
	if txErr != nil {
		return errs.CreateAndLogInternalError(txErr, "Failed to begin transaction for reviewing register request").
			AppendDetails("注册请求审核失败")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var req model.RegisterRequest
	err := tx.QueryRow(ctx, lockRegisterRequestSQL, id).Scan(
		&req.ID,
		&req.Username,
		&req.Password,
		&req.Type,
		&req.StudentNum,
		&req.RealName,
		&req.School,
		&req.Nickname,
		&req.Status,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("注册请求不存在")
		}
		return errs.CreatePGError(err, "注册请求", "Failed to lock register request")
	}
	if req.Status != model.RegisterRequestStatusPending {
		return errs.ConflictError().AppendDetails("注册请求已被审核")
	}

	if status == model.RegisterRequestStatusRejected {
		if _, e := tx.Exec(ctx, rejectRegisterRequestSQL, id, status, reviewerID, reviewComment); e != nil {
			return errs.CreatePGError(e, "注册请求", "Failed to reject register request")
		}
		if e := tx.Commit(ctx); e != nil {
			return errs.CreateAndLogInternalError(e, "Failed to commit transaction for rejecting register request").
				AppendDetails("注册请求审核失败")
		}

		db.R.Del(ctx, UsernameExistsCacheKey(req.Username))
		slog.Info("Register request rejected", "register_id", id, "reviewer_id", reviewerID)
		return nil
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
	// 排除当前申请自身，否则事务内仍为 pending 的申请会被唯一性查询判为已占用
	excludeRegisterRequestID := req.ID
	if err := createUserWithPasswordAt(ctx, tx, u, pwd, &excludeRegisterRequestID); err != nil {
		return err
	}

	if _, e := tx.Exec(ctx, approveRegisterRequestSQL, id, u.ID, reviewerID, reviewComment); e != nil {
		return errs.CreatePGError(e, "注册请求", "Failed to approve register request")
	}
	if e := tx.Commit(ctx); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to commit transaction for approving register request").
			AppendDetails("注册请求审核失败")
	}

	db.SetRedis(ctx, UserIDCacheKey(u.Username), u.ID, UserCacheDuration)
	db.SetRedis(ctx, UserCacheKey(u.ID), u, UserCacheDuration)
	db.R.Del(ctx, UsernameExistsCacheKey(u.Username))

	slog.Info("User created", "user_id", u.ID, "username", u.Username, "type", u.Type, "school", u.School)
	slog.Info("Register request approved", "register_id", id, "user_id", u.ID, "reviewer_id", reviewerID)

	return nil
}

// ---------------------------------------------------------------------------
// 删除注册请求
// ---------------------------------------------------------------------------

// deleteRegisterRequestSQL 物理删除注册申请，返回用户名用于清理占用缓存。
const deleteRegisterRequestSQL = `
DELETE FROM register_requests
WHERE id = $1
RETURNING username
`

// DeleteRegisterRequest 物理删除注册申请并清理用户名占用缓存；注册流程上传佐证图片失败时用它回滚。
func DeleteRegisterRequest(ctx context.Context, id uuid.UUID) *errs.Error {
	var username string
	err := db.R.QueryRow(ctx, deleteRegisterRequestSQL, id).Scan(&username)
	if err != nil {
		return errs.CreatePGError(err, "注册请求", "Failed to delete register request")
	}

	db.R.Del(ctx, UsernameExistsCacheKey(username))

	return nil
}
