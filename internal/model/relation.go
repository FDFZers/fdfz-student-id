//go:generate go tool go-enum --names --values --marshal --sql
package model

import "time"

// ENUM(none, followed, following, friends)
type Relationship string

type UserFollow struct {
	ID          int64     `json:"id" db:"id"`
	FollowerID  int64     `json:"follower_id" db:"follower_id"`
	FollowingID int64     `json:"following_id" db:"following_id"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

type RelationList struct {
	Count int32
	Users []*User
}
