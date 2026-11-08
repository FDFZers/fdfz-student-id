package perm

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// PermissionInfo 是权限目录中的一条权限定义，由 permission_defs 行与所属应用命名空间拼接而来。
type PermissionInfo struct {
	ID          int64
	AppID       int64
	Namespace   string
	Value       string
	String      string
	Description string
	Requestable bool
	Nodes       []string
	Implies     []*PermissionInfo
}

// Catalog 是某一时刻全部有效权限定义及其继承关系的内存快照。
// 注意：快照发布后只读，重载时整体替换指针，不要在运行时修改其内容。
type Catalog struct {
	Defs        []*PermissionInfo
	ByString    map[string]*PermissionInfo
	ByNamespace map[string][]*PermissionInfo
}

var (
	// current 是当前生效的目录快照。读多写少，用 atomic.Pointer 实现无锁读取。
	current atomic.Pointer[Catalog]
)

// EmptyCatalog 返回不含任何权限定义的空目录，用于兜底与测试。
func EmptyCatalog() *Catalog {
	return &Catalog{
		ByString:    map[string]*PermissionInfo{},
		ByNamespace: map[string][]*PermissionInfo{},
	}
}

// Snapshot 返回当前目录快照；尚未加载过时返回空目录而不是 nil，调用方无需判空。
func Snapshot() *Catalog {
	if c := current.Load(); c != nil {
		return c
	}
	return EmptyCatalog()
}

// store 原子替换当前目录快照；nil 会被转为空目录，保证读取端始终拿到可用对象。
func store(c *Catalog) {
	if c == nil {
		c = EmptyCatalog()
	}
	current.Store(c)
}

// Load 从 PostgreSQL 重新加载权限目录，成功后原子替换全局快照。
// 注意：加载失败时保留旧快照不变，调用方应决定是否重试或继续使用旧数据。
func Load(ctx context.Context) *errs.Error {
	cat, err := loadCatalog(ctx)
	if err != nil {
		return err
	}
	store(cat)
	return nil
}

// loadCatalogSQL 只加载有效应用（active 且未删除）下的权限定义；应用停用后其权限不会进入快照。
// 字段顺序与下方 pgx.CollectRows 的 Scan 参数一一对应。
const loadCatalogSQL = `
SELECT p.id, p.app_id, a.namespace, p.value, p.description, p.requestable
FROM permission_defs p
JOIN oauth_apps a ON a.id = p.app_id
WHERE a.status = 'active'
  AND a.deleted_at IS NULL
ORDER BY p.id
`

// loadImpliesSQL 加载全部继承边；端点对应的定义若已失效，会在组装目录时被过滤。
const loadImpliesSQL = `
SELECT permission_id, implied_permission_id
FROM permission_implies
`

// loadCatalog 从数据库构建新的权限目录快照，包含权限定义去重、继承边过滤与继承环检测。
func loadCatalog(ctx context.Context) (*Catalog, *errs.Error) {
	cat := EmptyCatalog()

	// 加载权限定义并解析 value
	rows, err := db.R.Query(ctx, loadCatalogSQL)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限定义", "Failed to load permission defs").AppendDetails("权限定义加载失败")
	}
	defs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*PermissionInfo, error) {
		var info PermissionInfo
		if err := row.Scan(
			&info.ID, &info.AppID, &info.Namespace, &info.Value,
			&info.Description, &info.Requestable,
		); err != nil {
			return nil, err
		}
		info.String = Render(info.Namespace, info.Value)
		nodes, err := ParseNodes(info.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid permission value %q (id=%d): %w", info.Value, info.ID, err)
		}
		info.Nodes = nodes
		return &info, nil
	})
	if err != nil {
		return nil, errs.CreatePGError(err, "权限定义", "Failed to collect permission defs").AppendDetails("权限定义加载失败")
	}

	// 校验完整性：完整权限串不允许重复（数据库有 (app_id, value) 唯一约束，此处为防御性校验）
	defByID := make(map[int64]*PermissionInfo, len(defs))
	for _, def := range defs {
		if _, ok := cat.ByString[def.String]; ok {
			return nil, errs.CreateAndLogInternalError(fmt.Errorf("duplicate permission %q", def.String), "Duplicate permission", "permission", def.String).
				AppendDetails("权限存在重复定义", "权限定义加载失败")
		}
		cat.ByString[def.String] = def
		cat.ByNamespace[def.Namespace] = append(cat.ByNamespace[def.Namespace], def)
		defByID[def.ID] = def
	}

	// 加载并组装继承边
	implRows, err := db.R.Query(ctx, loadImpliesSQL)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to load permission implies").AppendDetails("权限继承加载失败")
	}
	type edge struct{ from, to int64 }
	var edges []edge
	for implRows.Next() {
		var from, to int64
		if err := implRows.Scan(&from, &to); err != nil {
			implRows.Close()
			return nil, errs.CreatePGError(err, "权限继承", "Failed to scan permission implies").AppendDetails("权限继承加载失败")
		}
		edges = append(edges, edge{from: from, to: to})
	}
	if err := implRows.Err(); err != nil {
		implRows.Close()
		return nil, errs.CreatePGError(err, "权限继承", "Failed to read permission implies").AppendDetails("权限继承加载失败")
	}
	implRows.Close()

	for _, e := range edges {
		from, ok1 := defByID[e.from]
		to, ok2 := defByID[e.to]
		// 任一端被禁用/下线时静默忽略该边
		if !ok1 || !ok2 {
			continue
		}
		if from.AppID != to.AppID {
			return nil, errs.CreateAndLogInternalError(fmt.Errorf("cross-app permission implies: %s -> %s", from.String, to.String), "Cross-app permission implies", "from", from.String, "to", to.String).
				AppendDetails("权限继承关系不能跨应用", "权限继承加载失败")
		}
		from.Implies = append(from.Implies, to)
	}

	cat.Defs = defs

	// 校验继承图无环；有环时拒绝整份快照
	if err := validateCycleImplies(cat); err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Permission implies cycle detected").AppendDetails("权限存在循环继承", "权限继承加载失败")
	}

	return cat, nil
}

// validateCycleImplies 检查目录中的继承图是否存在环；有环时返回包含环上权限串的可读错误。
func validateCycleImplies(cat *Catalog) error {
	defByID := make(map[int64]*PermissionInfo, len(cat.Defs))
	edges := make(map[int64][]int64, len(cat.Defs))
	for _, def := range cat.Defs {
		defByID[def.ID] = def
		for _, implied := range def.Implies {
			edges[def.ID] = append(edges[def.ID], implied.ID)
		}
	}

	cycle := DetectCycle(edges)
	if cycle == nil {
		return nil
	}

	parts := make([]string, len(cycle))
	for i, id := range cycle {
		parts[i] = defByID[id].String
	}
	return fmt.Errorf("permission implies cycle detected: %s", strings.Join(parts, " -> "))
}
