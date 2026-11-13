package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Handle 是连接池与事务共用的数据库句柄。
// 需要事务的 service 接收该接口，Begin 后把返回的 pgx.Tx 继续传给后续操作。
type Handle interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

var (
	_ Handle = (*Repo)(nil)
	_ Handle = (pgx.Tx)(nil)
)
