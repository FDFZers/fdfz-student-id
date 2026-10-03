package user

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/perm"
	"log/slog"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// 获取权限
// ---------------------------------------------------------------------------

const getUserPermsSQL = `
SELECT permission
FROM user_permissions
WHERE user_id = $1
  AND enabled = true
  AND (valid_from  IS NULL OR valid_from  <= now())
  AND (valid_until IS NULL OR valid_until >  now())
ORDER BY permission
`

func GetUserPerms(
	ctx context.Context,
	userID int64,
) ([]string, *errs.Error) {
	rows, err := db.R.Query(ctx, getUserPermsSQL, userID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户权限", "Failed to get user permissions").AppendDetails("用户权限获取失败")
	}
	defer rows.Close()

	perms, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, errs.CreatePGError(err, "用户权限", "Failed to get user permissions").AppendDetails("用户权限获取失败")
	}

	for _, p := range perms {
		if ok, err := perm.RegexPermUser.MatchString(p); err != nil {
			return nil, errs.CreateAndLogInternalError(err, "用户权限", "Failed to validate permission").AppendDetails("权限校验失败", "用户权限获取失败")
		} else if !ok {
			slog.Error("Invalid user permission", "userID", userID, "permission", p)
			return nil, errs.InternalError().AppendDetails("存在无效用户权限", "用户权限获取失败")
		}
	}

	return perms, nil
}
