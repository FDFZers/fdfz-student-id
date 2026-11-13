package db

import (
	"context"
	"embed"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PDB 包装 pgxpool 连接池，供服务层通过 db.R 执行 SQL。
type PDB struct {
	*pgxpool.Pool
}

// NewDB 解析 POSTGRESQL_URL 并创建连接池，启动时做一次 5 秒超时的连通性检查。
// 注意：Ping 失败会关闭连接池并返回错误，调用方不应继续使用该 Pool。
func NewDB() (*PDB, error) {
	c, err := pgxpool.ParseConfig(cfg.C.PostgresURL)
	if err != nil {
		return nil, fmt.Errorf("postgresql: failed to parse dsn: %w", err)
	}

	// 连接池参数
	c.MaxConns = 25
	c.MinConns = 5
	c.MaxConnLifetime = 5 * time.Minute
	c.MaxConnIdleTime = 1 * time.Minute
	c.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), c)
	if err != nil {
		return nil, fmt.Errorf("postgresql: failed to create pool: %w", err)
	}

	// 验证连通性
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgresql: failed to ping database: %w", err)
	}

	return &PDB{Pool: pool}, nil
}

// fs 内嵌 internal/db/migrations 下的迁移 SQL 文件。
//
//go:embed migrations/*.sql
var fs embed.FS

// RunMigrations 执行内嵌迁移到最新版本，无变更（ErrNoChange）视为成功。
// 注意：golang-migrate 的驱动名为 pgx5，因此需要把连接串的 postgres:// / postgresql:// 前缀替换掉。
func RunMigrations() error {
	source, err := iofs.New(fs, "migrations")
	if err != nil {
		return err
	}

	r := strings.NewReplacer(
		"postgres://", "pgx5://",
		"postgresql://", "pgx5://",
	)
	m, err := migrate.NewWithSourceInstance("iofs", source, r.Replace(cfg.C.PostgresURL))
	if err != nil {
		return err
	}
	defer func(m *migrate.Migrate) {
		e, err := m.Close()
		if e != nil || err != nil {
			slog.Warn("Failed to close migration database", "sourceErr", e, "dbErr", err)
		}
	}(m)

	// 应用全部待执行迁移
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
