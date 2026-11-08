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

// RegisterRequestCacheDuration 是注册申请详情缓存时长。
const RegisterRequestCacheDuration = 5 * time.Minute

// RegisterRequestCacheKey 返回注册申请缓存的 Redis key（按申请 UUID）。
func RegisterRequestCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:register_request:id:%s", id)
}

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

// CreateRegisterRequest 创建注册申请（r.Password 必须已哈希）：先校验用户名/学号占用，再写库并刷新缓存。
// 注意：用户名与学号冲突统一返回模糊文案，避免被用来探测某个用户名/学号是否已被占用。
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

	// 写入申请并刷新用户名占用缓存与申请缓存

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
		return errs.CreatePGError(e, "注册请求", "Failed to create register request")
	}

	db.R.Del(ctx, UsernameExistsCacheKey(r.Username))
	db.SetRedis(ctx, RegisterRequestCacheKey(r.ID), r, RegisterRequestCacheDuration)

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

// GetRegisterRequestByID 按 ID 查询注册申请：优先读缓存，未命中时回源 PostgreSQL。
// 返回 nil 表示申请不存在，不返回错误。
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
		return nil, err
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// 审核注册请求
// ---------------------------------------------------------------------------

// reviewRegisterRequestSQL 仅允许把待审核申请改为目标状态，并记录审核人、意见与审核时间。
const reviewRegisterRequestSQL = `
UPDATE register_requests
SET status = $2, reviewer_user_id = $3, review_comment = $4, reviewed_at = now()
WHERE id = $1 AND status = 'pending'
RETURNING username, reviewed_at
`

// rollbackReviewSQL 把审核通过但后续步骤失败的申请回退为待审核，并清空审核人与审核时间。
const rollbackReviewSQL = `
UPDATE register_requests
SET status = 'pending',
    created_user_id = NULL,
    reviewer_user_id = NULL,
    reviewed_at = NULL
WHERE id = $1 AND status = 'approved'
`

// setRegisterRequestCreatedUserSQL 回写审核通过时创建的用户 ID。
const setRegisterRequestCreatedUserSQL = `
UPDATE register_requests
SET created_user_id = $2
WHERE id = $1 AND status = 'approved'
`

// ReviewRegisterRequest 审核注册申请：先更新状态并记录审核人/意见，审核通过时再创建用户并回写用户 ID。
// 注意：状态更新与创建用户不在同一事务内，创建用户失败时依赖 rollbackReviewSQL 补偿回退为待审核。
// 注意：回滚 SQL 不重置 review_comment，失败回退后可能残留本次审核意见。
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
		return errs.BadRequestError().AppendDetails("不能将注册请求标记为待审核")
	}

	// 更新审核状态并失效注册申请/用户名占用缓存

	e := db.R.QueryRow(ctx, reviewRegisterRequestSQL, id, status, reviewerID, reviewComment).Scan(&username, &reviewedAt)
	if e != nil {
		return errs.CreatePGError(e, "注册请求", "Failed to review register request")
	}

	db.R.Del(ctx, RegisterRequestCacheKey(id))
	db.R.Del(ctx, UsernameExistsCacheKey(username))

	// 仅审核通过时创建用户

	if status != model.RegisterRequestStatusApproved {
		return nil
	}

	// 返回错误前先尝试把申请回滚为待审核，回滚失败时提示联系管理员

	rollback := func(err *errs.Error) *errs.Error {
		if _, e := db.R.Exec(ctx, rollbackReviewSQL, id); e != nil {
			details := errs.CreatePGError(e, "注册请求", "Failed to rollback review").Info.Details
			return err.AppendDetails("注册请求状态回退失败，请联系管理员").AppendDetails(details...)
		}
		return err.AppendDetails("注册请求已回退为待审核")
	}

	req, err := GetRegisterRequestByID(ctx, id)
	if err != nil {
		return rollback(err)
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
	if err := CreateUser(ctx, u, pwd); err != nil {
		return rollback(err)
	}

	// 回写创建的用户 ID；失败不回滚用户，仅记录日志

	if _, e := db.R.Exec(ctx, setRegisterRequestCreatedUserSQL, id, u.ID); e != nil {
		slog.Error("Failed to set created user for register request", "error", e, "register_id", id, "user_id", u.ID)
	}

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

// DeleteRegisterRequest 物理删除注册申请并清理缓存；注册流程上传佐证图片失败时用它回滚。
func DeleteRegisterRequest(ctx context.Context, id uuid.UUID) *errs.Error {
	var username string
	err := db.R.QueryRow(ctx, deleteRegisterRequestSQL, id).Scan(&username)
	if err != nil {
		return errs.CreatePGError(err, "注册请求", "Failed to delete register request")
	}

	db.R.Del(ctx, RegisterRequestCacheKey(id))
	db.R.Del(ctx, UsernameExistsCacheKey(username))

	return nil
}
