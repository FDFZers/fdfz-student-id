package user

import (
	"context"
	"encoding/json"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

const (
	FollowListDefaultLimit int32 = 20
	FollowListMaxLimit     int32 = 100
)

func listFollows(
	ctx context.Context,
	item string,
	countSQL string,
	listSQL string,
	userID int64,
	limit, offset int32,
) (*model.FollowList, *errs.Error) {
	if limit <= 0 {
		limit = FollowListDefaultLimit
	}
	if limit > FollowListMaxLimit {
		limit = FollowListMaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	var count int32
	if err := db.R.QueryRow(ctx, countSQL, userID).Scan(&count); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to count follow list").AppendDetails(item + "获取失败")
	}

	rows, err := db.R.Query(ctx, listSQL, userID, limit, offset)
	if err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to query follow list").AppendDetails(item + "获取失败")
	}

	users, uErr := collectFollowUsers(rows, item)
	if uErr != nil {
		return nil, uErr
	}

	return &model.FollowList{Count: count, Users: users}, nil
}

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
			return nil, errs.CreatePGError(err, item, "Failed to scan follow list").AppendDetails(item + "获取失败")
		}
		if err := json.Unmarshal(vis, &u.Visibilities); err != nil {
			return nil, errs.CreateAndLogInternalError(err, "Failed to unmarshal user visibilities").
				AppendDetails("用户可见性解析失败", item+"获取失败")
		}
		u.Visibilities.Normalize()
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate follow list").AppendDetails(item + "获取失败")
	}

	return users, nil
}

// ---------------------------------------------------------------------------
// 关注
// ---------------------------------------------------------------------------

const followUserSQL = `
INSERT INTO user_follows (follower_id, following_id)
VALUES ($1, $2)
ON CONFLICT (follower_id, following_id) DO NOTHING
`

func FollowUser(ctx context.Context, followerID, followingID int64) *errs.Error {
	if followerID == followingID {
		return errs.BadRequestError().AppendDetails("不能关注自己", "关注失败")
	}
	if _, err := db.R.Exec(ctx, followUserSQL, followerID, followingID); err != nil {
		return errs.CreatePGError(err, "关注", "Failed to follow user").AppendDetails("关注失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 取消关注
// ---------------------------------------------------------------------------

const unfollowUserSQL = `
DELETE FROM user_follows
WHERE follower_id = $1 AND following_id = $2
`

func UnfollowUser(ctx context.Context, followerID, followingID int64) *errs.Error {
	if _, err := db.R.Exec(ctx, unfollowUserSQL, followerID, followingID); err != nil {
		return errs.CreatePGError(err, "关注", "Failed to unfollow user").AppendDetails("取消关注失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 关注关系
// ---------------------------------------------------------------------------

const getFollowRelationshipSQL = `
SELECT
    EXISTS (SELECT 1 FROM user_follows WHERE follower_id = $1 AND following_id = $2),
    EXISTS (SELECT 1 FROM user_follows WHERE follower_id = $2 AND following_id = $1)
`

func GetFollowRelationship(ctx context.Context, viewerID, targetID int64) (model.FollowRelationship, *errs.Error) {
	var following, followedBy bool
	err := db.R.QueryRow(ctx, getFollowRelationshipSQL, viewerID, targetID).
		Scan(&following, &followedBy)
	if err != nil {
		return "", errs.CreatePGError(err, "关注关系", "Failed to get follow relationship")
	}

	if following && followedBy {
		return model.FollowRelationshipFriends, nil
	} else if following {
		return model.FollowRelationshipFollowing, nil
	} else if followedBy {
		return model.FollowRelationshipFollowed, nil
	}

	return model.FollowRelationshipNone, nil
}

// ---------------------------------------------------------------------------
// 粉丝列表
// ---------------------------------------------------------------------------

const listFollowersSQL = `
SELECT u.id, u.username, u.type, u.student_num, u.real_name, u.school,
    u.nickname, u.signature, u.bio, u.visibilities,
    u.created_at, u.updated_at, u.deleted_at
FROM user_follows f
JOIN users u ON u.id = f.follower_id
WHERE f.following_id = $1 AND u.deleted_at IS NULL
ORDER BY f.created_at DESC, u.id DESC
LIMIT $2 OFFSET $3`

func ListFollowers(ctx context.Context, userID int64, limit, offset int32) (*model.FollowList, *errs.Error) {
	return listFollows(ctx, "粉丝列表", countFollowersSQL, listFollowersSQL, userID, limit, offset)
}

const countFollowersSQL = `
SELECT count(*)
FROM user_follows f
JOIN users u ON u.id = f.follower_id
WHERE f.following_id = $1 AND u.deleted_at IS NULL
`

func CountFollowers(ctx context.Context, userID int64) (int64, *errs.Error) {
	var count int64
	if err := db.R.QueryRow(ctx, countFollowersSQL, userID).Scan(&count); err != nil {
		return 0, errs.CreatePGError(err, "粉丝列表", "Failed to count follower list")
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// 关注列表
// ---------------------------------------------------------------------------

const listFollowingSQL = `
SELECT u.id, u.username, u.type, u.student_num, u.real_name, u.school,
    u.nickname, u.signature, u.bio, u.visibilities,
    u.created_at, u.updated_at, u.deleted_at
FROM user_follows f
JOIN users u ON u.id = f.following_id
WHERE f.follower_id = $1 AND u.deleted_at IS NULL
ORDER BY f.created_at DESC, u.id DESC
LIMIT $2 OFFSET $3`

func ListFollowing(ctx context.Context, userID int64, limit, offset int32) (*model.FollowList, *errs.Error) {
	return listFollows(ctx, "关注列表", countFollowingSQL, listFollowingSQL, userID, limit, offset)
}

const countFollowingSQL = `
SELECT count(*)
FROM user_follows f
JOIN users u ON u.id = f.following_id
WHERE f.follower_id = $1 AND u.deleted_at IS NULL
`

func CountFollowing(ctx context.Context, userID int64) (int64, *errs.Error) {
	var count int64
	if err := db.R.QueryRow(ctx, countFollowingSQL, userID).Scan(&count); err != nil {
		return 0, errs.CreatePGError(err, "关注列表", "Failed to count following list")
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// 好友列表
// ---------------------------------------------------------------------------

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

func ListFriends(ctx context.Context, userID int64, limit, offset int32) (*model.FollowList, *errs.Error) {
	return listFollows(ctx, "好友列表", countFriendsSQL, listFriendsSQL, userID, limit, offset)
}

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
		return 0, errs.CreatePGError(err, "好友列表", "Failed to count friend list")
	}
	return count, nil
}
