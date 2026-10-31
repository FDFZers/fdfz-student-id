package perm

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
)

type PermissionDef struct {
	Public       bool
	Nodes        []string
	Placeholders []string
	Parents      []*PermissionDef
}

var (
	PermissionDefs []PermissionDef
)

const getAllPermsSQL = `
SELECT id, value, parents, public
FROM permissions
`

type rawDef struct {
	ID        int64
	Value     string
	ParentIDs []int64
	Public    bool
}

func LoadDefinitions(ctx context.Context) *errs.Error {
	rows, err := db.R.Query(ctx, getAllPermsSQL)
	if err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to query permissions").AppendDetails("权限加载失败")
	}

	raws, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*rawDef, error) {
		var raw rawDef
		if err := row.Scan(&raw.ID, &raw.Value, &raw.ParentIDs, &raw.Public); err != nil {
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
			return errs.CreateAndLogInternalError(err, "Failed to validate permission definition", "id", raw.ID, "value", raw.Value).
				AppendDetails("权限校验失败", "权限加载失败")
		} else if !ok {
			return errs.CreateAndLogInternalError(errors.New("invalid permission definition"), "Invalid permission definition", "id", raw.ID, "value", raw.Value).
				AppendDetails("存在无效权限", "权限加载失败")
		}
		nodes := GetNodes(raw.Value)
		defMap[raw.ID] = &PermissionDef{Nodes: nodes, Placeholders: GetPlaceholders(nodes), Public: raw.Public}
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
				return errs.CreateAndLogInternalError(fmt.Errorf("parent permission %d not found", pid), "Parent permission not found", "id", id, "parentID", pid).
					AppendDetails("存在未知父权限", "权限加载失败")
			}
			def.Parents = append(def.Parents, parent)
		}
		defs = append(defs, *def)
	}

	PermissionDefs = defs
	return nil
}
