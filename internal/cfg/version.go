package cfg

import "os"

// 构建信息：由 Dockerfile 在编译时通过 -ldflags -X 注入。
var (
	Commit    = "dev" // 构建对应的 Git commit
	BuildTime = "dev" // 构建时间（UTC，ISO 8601）
	IsProd    = os.Getenv("APP_ENV") == "prod"
)
