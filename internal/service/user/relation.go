package user

import (
	"context"
	"encoding/json/v2"
	searchsvc "fdfz-student-id/internal/service/search"
	"fmt"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

const (
	FollowCacheDuration = 1 * time.Minute
)

// FollowRelationshipCacheKey 返回「viewer 对 target」关注关系缓存的 Redis key（有方向）。
func FollowRelationshipCacheKey(viewerID, targetID int64) string {
	return fmt.Sprintf("student_id:user:follow:rel:%d:%d", viewerID, targetID)
}

func invalidateFollowCache(ctx context.Context, followerID, followingID int64) {
	db.R.Del(ctx,
		FollowRelationshipCacheKey(followerID, followingID),
		FollowRelationshipCacheKey(followingID, followerID),
	)
}

// listFollows 是三个关系列表接口的公共实现：归一化分页参数后分别查询总数与列表，并解析用户可见性。
// item 是「粉丝列表/关注列表/好友列表」等中文名词，用于错误 details 与日志。
// 注意：总数与列表是两次独立查询，并发关注/取关时两者的结果可能不一致。
func listFollows(
	ctx context.Context,
	item string,
	countSQL string,
	listSQL string,
	userID int64,
	limit, offset int32,
) (*model.RelationList, *errs.Error) {
	// 分页参数归一化：limit 落在 [1, MaxLimit]，offset 不小于 0

	if limit <= 0 {
		limit = searchsvc.DefaultLimit
	}
	if limit > searchsvc.MaxLimit {
		limit = searchsvc.MaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	var count int32
	if e := db.R.QueryRow(ctx, countSQL, userID).Scan(&count); e != nil {
		return nil, errs.CreatePGError(e, item, "Failed to count follow list")
	}

	rows, e := db.R.Query(ctx, listSQL, userID, limit, offset)
	if e != nil {
		return nil, errs.CreatePGError(e, item, "Failed to query follow list")
	}

	users, err := collectFollowUsers(rows, item)
	if err != nil {
		return nil, err
	}

	return &model.RelationList{Count: count, Users: users}, nil
}

// collectFollowUsers 逐行扫描关系列表的用户记录并解析 visibilities JSON；已软删除用户由 SQL 过滤。
func collectFollowUsers(rows pgx.Rows, item string) ([]*model.User, *errs.Error) {
	defer rows.Close()

	users := make([]*model.User, 0)
	for rows.Next() {
		var (
			u   model.User
			vis []byte
		)
		if err := rows.Scan(
			&u.ID, &u.Username, &u.Type, &u.StudentNum, &u.RealName, &u.School,
			&u.Nickname, &u.Signature, &u.Bio, &vis,
			&u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, item, "Failed to scan follow list")
		}
		if err := json.Unmarshal(vis, &u.Visibilities); err != nil {
			return nil, errs.CreateAndLogInternalError(err, "Failed to unmarshal user visibilities").
				AppendDetails("用户可见性解析失败")
		}
		u.Visibilities.Normalize()
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate follow list")
	}

	return users, nil
}

// ---------------------------------------------------------------------------
// 关注
// ---------------------------------------------------------------------------

// followUserSQL 插入关注关系；重复关注通过 ON CONFLICT DO NOTHING 保持幂等。
const followUserSQL = `
INSERT INTO user_follows (follower_id, following_id)
VALUES ($1, $2)
ON CONFLICT (follower_id, following_id) DO NOTHING
`

// FollowUser 建立关注关系并失效相关缓存；重复关注不报错。
// 注意：不能关注自己；不校验被关注者是否存在，调用方需先确认。
func FollowUser(ctx context.Context, followerID, followingID int64) *errs.Error {
	if followerID == followingID {
		return errs.BadRequestError().AppendDetails("不能关注自己")
	}
	if _, err := db.R.Exec(ctx, followUserSQL, followerID, followingID); err != nil {
		return errs.CreatePGError(err, "关注", "Failed to follow user")
	}
	invalidateFollowCache(ctx, followerID, followingID)
	return nil
}

// ---------------------------------------------------------------------------
// 取消关注
// ---------------------------------------------------------------------------

// unfollowUserSQL 删除关注关系；未关注时删除 0 行，保持幂等。
const unfollowUserSQL = `
DELETE FROM user_follows
WHERE follower_id = $1 AND following_id = $2
`

// UnfollowUser 删除关注关系并失效相关缓存；未关注时视为成功。
func UnfollowUser(ctx context.Context, followerID, followingID int64) *errs.Error {
	if _, err := db.R.Exec(ctx, unfollowUserSQL, followerID, followingID); err != nil {
		return errs.CreatePGError(err, "关注", "Failed to unfollow user")
	}
	invalidateFollowCache(ctx, followerID, followingID)
	return nil
}

// ---------------------------------------------------------------------------
// 关注关系
// ---------------------------------------------------------------------------

// getFollowRelationshipSQL 同时查询 viewer 是否关注 target、target 是否关注 viewer。
const getFollowRelationshipSQL = `
SELECT
    EXISTS (SELECT 1 FROM user_follows WHERE follower_id = $1 AND following_id = $2),
    EXISTS (SELECT 1 FROM user_follows WHERE follower_id = $2 AND following_id = $1)
`

// GetFollowRelationship 查询 viewer 与 target 之间的关系：none/followed/following/friends，结果缓存 1 分钟。
// 注意：关系有方向，viewer/target 反过来查询结果可能不同（following 与 followed 互换）。
func GetFollowRelationship(ctx context.Context, viewerID, targetID int64) (model.Relationship, *errs.Error) {
	rel, err := db.GetCached(
		ctx,
		"关注关系",
		FollowRelationshipCacheKey(viewerID, targetID),
		FollowCacheDuration,
		func() (*model.Relationship, error) {
			var following, followedBy bool
			if err := db.R.QueryRow(ctx, getFollowRelationshipSQL, viewerID, targetID).
				Scan(&following, &followedBy); err != nil {
				return nil, err
			}

			var r model.Relationship
			switch {
			case following && followedBy:
				r = model.RelationshipFriends
			case following:
				r = model.RelationshipFollowing
			case followedBy:
				r = model.RelationshipFollowed
			default:
				r = model.RelationshipNone
			}
			return &r, nil
		},
	)
	if err != nil {
		return "", err
	}
	if rel == nil {
		return model.RelationshipNone, nil
	}
	return *rel, nil
}

// ---------------------------------------------------------------------------
// 粉丝列表
// ---------------------------------------------------------------------------

// listFollowersSQL 列出关注该用户的用户（不含已软删除用户），按关注时间倒序分页。
const listFollowersSQL = `
SELECT u.id, u.username, u.type, u.student_num, u.real_name, u.school,
    u.nickname, u.signature, u.bio, u.visibilities,
    u.created_at, u.updated_at, u.deleted_at
FROM user_follows f
JOIN users u ON u.id = f.follower_id
WHERE f.following_id = $1 AND u.deleted_at IS NULL
ORDER BY f.created_at DESC, u.id DESC
LIMIT $2 OFFSET $3`

// ListFollowers 获取用户的粉丝列表。
func ListFollowers(ctx context.Context, userID int64, limit, offset int32) (*model.RelationList, *errs.Error) {
	return listFollows(ctx, "粉丝列表", countFollowersSQL, listFollowersSQL, userID, limit, offset)
}

// countFollowersSQL 统计关注该用户的用户数（不含已软删除用户）。
const countFollowersSQL = `
SELECT count(*)
FROM user_follows f
JOIN users u ON u.id = f.follower_id
WHERE f.following_id = $1 AND u.deleted_at IS NULL
`

func CountFollowers(ctx context.Context, userID int64) (int64, *errs.Error) {
	var count int64
	if err := db.R.QueryRow(ctx, countFollowersSQL, userID).Scan(&count); err != nil {
		return 0, errs.CreatePGError(err, "粉丝列表", "Failed to count followers")
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// 关注列表
// ---------------------------------------------------------------------------

// listFollowingSQL 列出该用户关注的用户（不含已软删除用户），按关注时间倒序分页。
const listFollowingSQL = `
SELECT u.id, u.username, u.type, u.student_num, u.real_name, u.school,
    u.nickname, u.signature, u.bio, u.visibilities,
    u.created_at, u.updated_at, u.deleted_at
FROM user_follows f
JOIN users u ON u.id = f.following_id
WHERE f.follower_id = $1 AND u.deleted_at IS NULL
ORDER BY f.created_at DESC, u.id DESC
LIMIT $2 OFFSET $3`

// ListFollowing 获取用户的关注列表。
func ListFollowing(ctx context.Context, userID int64, limit, offset int32) (*model.RelationList, *errs.Error) {
	return listFollows(ctx, "关注列表", countFollowingSQL, listFollowingSQL, userID, limit, offset)
}

// countFollowingSQL 统计该用户关注的用户数（不含已软删除用户）。
const countFollowingSQL = `
SELECT count(*)
FROM user_follows f
JOIN users u ON u.id = f.following_id
WHERE f.follower_id = $1 AND u.deleted_at IS NULL
`

func CountFollowing(ctx context.Context, userID int64) (int64, *errs.Error) {
	var count int64
	if err := db.R.QueryRow(ctx, countFollowingSQL, userID).Scan(&count); err != nil {
		return 0, errs.CreatePGError(err, "关注列表", "Failed to count followings")
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// 好友列表
// ---------------------------------------------------------------------------

// listFriendsSQL 通过自连接 user_follows 找出互相关注的用户（不含已软删除用户）。
const listFriendsSQL = `
SELECT u.id, u.username, u.type, u.student_num, u.real_name, u.school,
    u.nickname, u.signature, u.bio, u.visibilities,
    u.created_at, u.updated_at, u.deleted_at
FROM user_follows f
JOIN user_follows b ON b.follower_id = f.following_id AND b.following_id = f.follower_id
JOIN users u ON u.id = f.following_id
WHERE f.follower_id = $1 AND u.deleted_at IS NULL
ORDER BY f.created_at DESC, u.id DESC
LIMIT $2 OFFSET $3`

// ListFriends 获取用户的好友列表（互相关注的用户）。
func ListFriends(ctx context.Context, userID int64, limit, offset int32) (*model.RelationList, *errs.Error) {
	return listFollows(ctx, "好友列表", countFriendsSQL, listFriendsSQL, userID, limit, offset)
}

// countFriendsSQL 统计用户的好友数（互相关注且对方未被软删除）。
const countFriendsSQL = `
SELECT count(*)
FROM user_follows f
JOIN user_follows b ON b.follower_id = f.following_id AND b.following_id = f.follower_id
JOIN users u ON u.id = f.following_id
WHERE f.follower_id = $1 AND u.deleted_at IS NULL
`

func CountFriends(ctx context.Context, userID int64) (int64, *errs.Error) {
	var count int64
	if err := db.R.QueryRow(ctx, countFriendsSQL, userID).Scan(&count); err != nil {
		return 0, errs.CreatePGError(err, "好友列表", "Failed to count friends")
	}
	return count, nil
}
