//go:generate go tool go-enum --names --values --marshal --sql

package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// ENUM(student, teacher)
type UserType string

// ENUM(FDFZ = fdfz,FFXH = ffxh,FFQP = ffqp,FFPD = ffpd, FFJA = ffja)
type School string

// ENUM(public, friends, private)
type Visibility string

type Visibilities struct {
	RealName  Visibility `json:"real_name"`
	Followers Visibility `json:"followers"`
	Following Visibility `json:"following"`
}

func (v *Visibilities) Normalize() {
	if v.RealName == "" {
		v.RealName = VisibilityPrivate
	}
	if v.Followers == "" {
		v.Followers = VisibilityPrivate
	}
	if v.Following == "" {
		v.Following = VisibilityPrivate
	}
}

type User struct {
	ID       int64  `json:"id" db:"id"`
	Username string `json:"username" db:"username"`

	Type       UserType    `json:"type" db:"type"`
	StudentNum null.String `json:"student_num" db:"student_num"`
	RealName   string      `json:"real_name" db:"real_name"`
	School     School      `json:"school" db:"school"`

	Nickname  null.String `json:"nickname" db:"nickname"`
	Signature string      `json:"signature" db:"signature"`
	Bio       string      `json:"bio" db:"bio"`

	Visibilities Visibilities `json:"visibilities" db:"visibilities"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"`
}

type UserBan struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Reason    string    `json:"reason" db:"reason"`
	EndTime   null.Time `json:"end_time" db:"end_time"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Enabled   bool      `json:"enabled" db:"enabled"`
}

type UserEmail struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Email     string    `json:"email" db:"email"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"`
}

type UserQQ struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	QQ        string    `json:"qq" db:"qq"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"`
}
