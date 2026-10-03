package search

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

func GetInfo(cfg *SearchConfig) *SearchInfo {
	fields := make([]string, 0, len(cfg.Fields))
	for _, field := range cfg.Fields {
		fields = append(fields, field.Column)
	}

	sortableFields := make([]string, 0, len(cfg.SortableFields))
	for _, field := range cfg.SortableFields {
		sortableFields = append(sortableFields, field.Column)
	}

	tags := make(map[string][]string, len(cfg.Tags))
	for _, tag := range cfg.Tags {
		values := make([]string, 0, len(tag.ValueMap))
		for _, value := range tag.ValueMap {
			values = append(values, value)
		}
		tags[tag.Column] = values
	}

	return &SearchInfo{
		Fields:         fields,
		MatchMethods:   cfg.MatchMethods,
		SortableFields: sortableFields,
		Tags:           tags,
	}
}

func ExecSearch[T any](ctx context.Context, cfg *SearchConfig, req *SearchRequest) (*SearchResult[T], *errs.Error) {
	query, err := BuildSearch(cfg, req)
	if err != nil {
		return nil, err
	}
	var count int32
	if err := db.R.QueryRow(ctx, query.Count.SQL, query.Count.Args...).Scan(&count); err != nil {
		return nil, errs.CreatePGError(err, cfg.Item, "Failed to execute search count query")
	}
	rows, dErr := db.R.Query(ctx, query.Data.SQL, query.Data.Args...)
	if dErr != nil {
		return nil, errs.CreatePGError(dErr, cfg.Item, "Failed to execute search data query")
	}
	data, dErr := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[T])
	if dErr != nil {
		return nil, errs.CreatePGError(dErr, cfg.Item, "Failed to collect search data")
	}
	return &SearchResult[T]{
		Count: count,
		Data:  data,
	}, nil
}

func BuildSearch(cfg *SearchConfig, req *SearchRequest) (*SearchQuery, *errs.Error) {
	fieldsByID := make(map[string]Field, len(cfg.Fields))
	for _, f := range cfg.Fields {
		fieldsByID[f.ID] = f
	}
	sortableByID := make(map[string]Field, len(cfg.SortableFields))
	for _, f := range cfg.SortableFields {
		sortableByID[f.ID] = f
	}
	tagsByID := make(map[string]Tag, len(cfg.Tags))
	for _, t := range cfg.Tags {
		tagsByID[t.ID] = t
	}
	allowedMatch := make(map[MatchMethod]struct{}, len(cfg.MatchMethods))
	for _, m := range cfg.MatchMethods {
		allowedMatch[m] = struct{}{}
	}

	method := req.MatchMethod
	if method == "" {
		method = MatchMethodContains
	}
	if _, ok := allowedMatch[method]; !ok {
		return nil, errs.BadRequestError().AppendDetails("未知匹配方法：" + string(method))
	}

	requested := req.Fields
	if len(requested) == 0 {
		requested = make([]string, 0, len(cfg.Fields))
		for _, f := range cfg.Fields {
			requested = append(requested, f.ID)
		}
	}
	searchFields := make([]Field, 0, len(requested))
	for _, id := range requested {
		f, ok := fieldsByID[id]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails("未知搜索字段：" + id)
		}
		searchFields = append(searchFields, f)
	}

	var conditions []sq.Sqlizer
	trimmed := strings.TrimSpace(req.Query)

	if trimmed != "" && len(searchFields) > 0 {
		orParts := make([]sq.Sqlizer, 0, len(searchFields))
		for _, f := range searchFields {
			if c := buildMatchCondition(f.Column, trimmed, method, req.CaseSensitive); c != nil {
				orParts = append(orParts, c)
			}
		}
		if len(orParts) > 0 {
			conditions = append(conditions, sq.Or(orParts))
		}
	}

	for tagID := range req.Tags {
		if _, ok := tagsByID[tagID]; !ok {
			return nil, errs.BadRequestError().AppendDetails("未知标签：" + tagID)
		}
	}

	for _, tag := range cfg.Tags {
		sel, ok := req.Tags[tag.ID]
		if !ok {
			continue
		}
		cond, err := buildTagCondition(tag, sel)
		if err != nil {
			return nil, err
		}
		if cond != nil {
			conditions = append(conditions, cond)
		}
	}

	countB := psql.Select("COUNT(*)").From(cfg.Table)
	dataB := psql.Select("*").From(cfg.Table)

	if len(conditions) > 0 {
		where := sq.And(conditions)
		countB = countB.Where(where)
		dataB = dataB.Where(where)
	}

	switch {
	case req.SortBy.Valid:
		f, ok := sortableByID[req.SortBy.String]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails("未知排序字段：" + req.SortBy.String)
		}
		var dir string
		switch string(req.SortOrder) {
		case "", string(SortOrderAscending):
			dir = "ASC"
		case string(SortOrderDescending):
			dir = "DESC"
		default:
			return nil, errs.BadRequestError().AppendDetails("未知排序顺序：" + string(req.SortOrder))
		}
		dataB = dataB.OrderBy(fmt.Sprintf("%s %s", f.Column, dir))

	case trimmed == "" && cfg.DefaultSortColumn != "":
		dataB = dataB.OrderBy(cfg.DefaultSortColumn)
	}

	if req.Limit > 0 {
		dataB = dataB.Limit(uint64(req.Limit))
	}
	if req.Offset > 0 {
		dataB = dataB.Offset(uint64(req.Offset))
	}

	countSQL, countArgs, err := countB.ToSql()
	if err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to build search count query", "table", cfg.Table).AppendDetails("SQL 语句构建失败")
	}
	dataSQL, dataArgs, err := dataB.ToSql()
	if err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to build search data query", "table", cfg.Table).AppendDetails("SQL 语句构建失败")
	}

	return &SearchQuery{
		Count: Query{SQL: countSQL, Args: countArgs},
		Data:  Query{SQL: dataSQL, Args: dataArgs},
	}, nil
}

func buildMatchCondition(col, query string, method MatchMethod, caseSensitive bool) sq.Sqlizer {
	likeOp := "ILIKE"
	reOp := "~*"
	if caseSensitive {
		likeOp = "LIKE"
		reOp = "~"
	}

	switch string(method) {
	case "exact":
		if caseSensitive {
			return sq.Eq{col: query}
		}
		return sq.Expr(fmt.Sprintf("lower(%s) = lower(?)", col), query)

	case "contains":
		return sq.Expr(
			fmt.Sprintf("%s %s ?", col, likeOp),
			"%"+escapeLike(query)+"%",
		)

	case "prefix":
		return sq.Expr(
			fmt.Sprintf("%s %s ?", col, likeOp),
			escapeLike(query)+"%",
		)

	case "suffix":
		return sq.Expr(
			fmt.Sprintf("%s %s ?", col, likeOp),
			"%"+escapeLike(query),
		)

	case "fuzzy":
		words := strings.Fields(query)
		if len(words) == 0 {
			return nil
		}
		parts := make([]sq.Sqlizer, 0, len(words))
		for _, w := range words {
			parts = append(parts, sq.Expr(
				fmt.Sprintf("%s %s ?", col, likeOp),
				"%"+escapeLike(w)+"%",
			))
		}
		return sq.And(parts)

	case "regex":
		return sq.Expr(fmt.Sprintf("%s %s ?", col, reOp), query)
	}
	return nil
}

func escapeLike(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	)
	return r.Replace(s)
}

func buildTagCondition(tag Tag, sel TagSelection) (sq.Sqlizer, *errs.Error) {
	reverse := make(map[string][]string, len(tag.ValueMap))
	for colVal, tagVal := range tag.ValueMap {
		reverse[tagVal] = append(reverse[tagVal], colVal)
	}

	var includeVals []string
	for _, id := range sel.Include {
		vals, ok := reverse[id]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails(fmt.Sprintf("未知标签：%s.%s", tag.ID, id))
		}
		includeVals = append(includeVals, vals...)
	}

	var excludeVals []string
	for _, id := range sel.Exclude {
		vals, ok := reverse[id]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails(fmt.Sprintf("未知标签：%s.%s", tag.ID, id))
		}
		excludeVals = append(excludeVals, vals...)
	}

	var parts []sq.Sqlizer
	if len(includeVals) > 0 {
		parts = append(parts, sq.Eq{tag.Column: includeVals})
	}
	if len(excludeVals) > 0 {
		parts = append(parts, sq.NotEq{tag.Column: excludeVals})
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return sq.And(parts), nil
}
