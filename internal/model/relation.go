//go:generate go tool go-enum --names --values --marshal --sql
package model

import "time"

// Relationship 两个用户之间的关注关系，none 表示无关系。
// ENUM(none, followed, following, friends)
type Relationship string

// UserFollow 关注关系，对应 user_follows 表；FollowerID 关注 FollowingID。
type UserFollow struct {
	ID          int64     `json:"id" db:"id"`
	FollowerID  int64     `json:"follower_id" db:"follower_id"`   // 关注者
	FollowingID int64     `json:"following_id" db:"following_id"` // 被关注者
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// RelationList 关系列表的查询结果，不分页接口直接返回总数与用户列表。
type RelationList struct {
	Count int32
	Users []*User
}
