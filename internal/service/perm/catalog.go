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

type Catalog struct {
	Defs        []*PermissionInfo
	ByString    map[string]*PermissionInfo
	ByNamespace map[string][]*PermissionInfo
}

var (
	current atomic.Pointer[Catalog]
)

func EmptyCatalog() *Catalog {
	return &Catalog{
		ByString:    map[string]*PermissionInfo{},
		ByNamespace: map[string][]*PermissionInfo{},
	}
}

func Snapshot() *Catalog {
	if c := current.Load(); c != nil {
		return c
	}
	return EmptyCatalog()
}

func store(c *Catalog) {
	if c == nil {
		c = EmptyCatalog()
	}
	current.Store(c)
}

func Load(ctx context.Context) *errs.Error {
	cat, err := loadCatalog(ctx)
	if err != nil {
		return err
	}
	store(cat)
	return nil
}

const loadCatalogSQL = `
SELECT p.id, p.app_id, a.namespace, p.value, p.description, p.requestable
FROM permission_defs p
JOIN oauth_apps a ON a.id = p.app_id
WHERE a.status = 'active'
  AND a.deleted_at IS NULL
ORDER BY p.id
`

const loadImpliesSQL = `
SELECT permission_id, implied_permission_id
FROM permission_implies
`

func loadCatalog(ctx context.Context) (*Catalog, *errs.Error) {
	cat := EmptyCatalog()

	rows, err := db.R.Query(ctx, loadCatalogSQL)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限定义", "Failed to load permission defs").AppendDetails("权限定义加载失败")
	}
	defs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*PermissionInfo, error) {
		var info PermissionInfo
		if scanErr := row.Scan(
			&info.ID, &info.AppID, &info.Namespace, &info.Value,
			&info.Description, &info.Requestable,
		); scanErr != nil {
			return nil, scanErr
		}
		info.String = Render(info.Namespace, info.Value)
		nodes, parseErr := ParseNodes(info.Value)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid permission value %q (id=%d): %w", info.Value, info.ID, parseErr)
		}
		info.Nodes = nodes
		return &info, nil
	})
	if err != nil {
		return nil, errs.CreatePGError(err, "权限定义", "Failed to collect permission defs").AppendDetails("权限定义加载失败")
	}

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

	// 继承
	implRows, err := db.R.Query(ctx, loadImpliesSQL)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to load permission implies").AppendDetails("权限继承加载失败")
	}
	type edge struct{ from, to int64 }
	var edges []edge
	for implRows.Next() {
		var from, to int64
		if scanErr := implRows.Scan(&from, &to); scanErr != nil {
			implRows.Close()
			return nil, errs.CreatePGError(scanErr, "权限继承", "Failed to scan permission implies").AppendDetails("权限继承加载失败")
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
				AppendDetails("权限继承关系不能跨应用", "权限定义加载失败")
		}
		from.Implies = append(from.Implies, to)
	}

	cat.Defs = defs

	if validateErr := validateCycleImplies(cat); validateErr != nil {
		return nil, errs.CreateAndLogInternalError(validateErr, "Permission implies cycle detected").AppendDetails("权限存在循环继承", "权限继承加载失败")
	}

	return cat, nil
}

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
