package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type PDB struct {
	*sqlx.DB
}

func NewDB() (*PDB, error) {
	// 从环境变量获取 URL
	dsn := os.Getenv("POSTGRESQL_URL")
	if dsn == "" {
		return nil, fmt.Errorf("postgresql: environment variable POSTGRESQL_URL not set")
	}

	db, err := sqlx.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgresql: failed to open connection: %w", err)
	}

	// 配置连接池
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	// 验证连通性
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgresql: failed to ping database: %w", err)
	}

	return &PDB{DB: db}, nil
}

//go:embed migrations/*.sql
var fs embed.FS

func RunMigrations() error {
	dsn := os.Getenv("POSTGRESQL_URL")
	if dsn == "" {
		return fmt.Errorf("postgresql: environment variable POSTGRESQL_URL not set")
	}
	source, err := iofs.New(fs, "migrations")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
