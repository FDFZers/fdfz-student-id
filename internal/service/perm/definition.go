package perm

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"log/slog"

	"github.com/jackc/pgx/v5"
)

type PermissionDef struct {
	Nodes        []string
	Placeholders []string
	Parents      []*PermissionDef
}

var (
	PermissionDefs []PermissionDef
)

const getAllPermsSQL = `
SELECT id, value, parents
FROM permissions
`

type rawDef struct {
	ID        int64
	Value     string
	ParentIDs []int64
}

func LoadDefinitions(ctx context.Context) *errs.Error {
	rows, err := db.R.Query(ctx, getAllPermsSQL)
	if err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to query permissions").AppendDetails("权限加载失败")
	}

	raws, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*rawDef, error) {
		var raw rawDef
		if err := row.Scan(&raw.ID, &raw.Value, &raw.ParentIDs); err != nil {
			return nil, err
		}
		return &raw, nil
	})
	if err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to collect rows").AppendDetails("权限加载失败")
	}

	defMap := make(map[int64]*PermissionDef, len(raws))
	parentIDsMap := make(map[int64][]int64, len(raws))
	for _, raw := range raws {
		if ok, err := RegexPermDefinition.MatchString(raw.Value); err != nil {
			slog.Warn("Failed to validate permission definition", "error", err, "id", raw.ID, "value", raw.Value)
			return errs.InternalError().AppendDetails("权限校验失败", "权限加载失败")
		} else if !ok {
			slog.Error("Invalid permission definition", "id", raw.ID, "value", raw.Value)
			return errs.InternalError().AppendDetails("存在无效权限", "权限加载失败")
		}
		nodes := GetNodes(raw.Value)
		defMap[raw.ID] = &PermissionDef{Nodes: nodes, Placeholders: GetPlaceholders(nodes)}
		parentIDsMap[raw.ID] = raw.ParentIDs
	}

	defs := make([]PermissionDef, 0, len(defMap))
	for id, def := range defMap {
		for _, pid := range parentIDsMap[id] {
			if pid == id {
				slog.Warn("Permission cannot be its own parent", "id", id)
				continue
			}
			parent, ok := defMap[pid]
			if !ok {
				slog.Warn("Parent permission not found", "id", id, "parentID", pid)
				return errs.InternalError().AppendDetails("存在未知父权限", "权限加载失败")
			}
			def.Parents = append(def.Parents, parent)
		}
		defs = append(defs, *def)
	}

	PermissionDefs = defs
	return nil
}
