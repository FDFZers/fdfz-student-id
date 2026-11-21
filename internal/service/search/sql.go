package search

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// psql 是统一使用 $n 占位符的 squirrel builder，所有条件均参数化，不拼接用户输入。
var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

const (
	DefaultLimit = 20  // 未指定 limit 时的默认分页大小
	MaxLimit     = 500 // 单次查询允许的最大分页大小，超过会被截断

	MaxQueryLength = 512

	MaxFuzzyWords = 8

	MaxFieldQueries = 20

	pgInvalidRegularExpression = "2201B"
)

// mapExecError 把搜索执行错误转换为 API 错误，其中正则表达式语法错误返回 400。
func mapExecError(err error, item, log string) *errs.Error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgInvalidRegularExpression {
		return errs.BadRequestError().AppendDetails("搜索表达式格式错误")
	}
	return errs.CreatePGError(err, item, log)
}

// GetInfo 把搜索配置转换为对外元信息。
// 注意：Tags 的标签值来自 map 遍历，每次返回的顺序可能不同，客户端应视为集合。
func GetInfo(cfg *SearchConfig) *SearchInfo {
	fields := make([]string, 0, len(cfg.Fields))
	for _, field := range cfg.Fields {
		fields = append(fields, field.ID)
	}

	sortableFields := make([]string, 0, len(cfg.SortableFields))
	for _, field := range cfg.SortableFields {
		sortableFields = append(sortableFields, field.ID)
	}

	tags := make(map[string][]string, len(cfg.Tags))
	for _, tag := range cfg.Tags {
		values := make([]string, 0, len(tag.ValueMap))
		for _, value := range tag.ValueMap {
			values = append(values, value)
		}
		tags[tag.ID] = values
	}

	return &SearchInfo{
		Fields:         fields,
		MatchMethods:   cfg.MatchMethods,
		SortableFields: sortableFields,
		Tags:           tags,
	}
}

// ExecSearch 执行搜索：先 COUNT 统计命中总数，再按分页查询数据并扫描为 T。
// 数据列按 db tag 映射到 T；Columns 未包含的字段保持零值。
func ExecSearch[T any](ctx context.Context, cfg *SearchConfig, req *SearchRequest) (*SearchResult[T], *errs.Error) {
	query, err := BuildSearch(cfg, req)
	if err != nil {
		return nil, err
	}
	// 统计总数
	var count int32
	if e := db.R.QueryRow(ctx, query.Count.SQL, query.Count.Args...).Scan(&count); e != nil {
		return nil, mapExecError(e, cfg.Item, "Failed to execute search count query")
	}
	// 查询当前页数据
	rows, e := db.R.Query(ctx, query.Data.SQL, query.Data.Args...)
	if e != nil {
		return nil, mapExecError(e, cfg.Item, "Failed to execute search data query")
	}
	data, e := pgx.CollectRows(rows, pgx.RowToAddrOfStructByNameLax[T])
	if e != nil {
		return nil, mapExecError(e, cfg.Item, "Failed to collect search data")
	}
	return &SearchResult[T]{
		Count: count,
		Data:  data,
	}, nil
}

// BuildSearch 根据配置与请求构建 COUNT 与数据查询两条参数化 SQL。
// 依次处理：白名单校验、关键词匹配、标签过滤、附加条件、排序与分页。
// 注意：所有字段/标签/排序标识都会先对照白名单，不合法时返回 bad_request。
func BuildSearch(cfg *SearchConfig, req *SearchRequest) (*SearchQuery, *errs.Error) {
	// 建立白名单索引，便于按 ID 查找并拒绝未知取值
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

	// 解析匹配方法（缺省 contains）
	var method MatchMethod
	if req.MatchMethod == nil {
		method = MatchMethodContains
	} else {
		method = *req.MatchMethod
	}
	if _, ok := allowedMatch[method]; !ok {
		return nil, errs.BadRequestError().AppendDetails("匹配方法不受支持：" + string(method))
	}

	// 解析大小写选项（缺省区分大小写）
	var caseSensitive bool
	if req.CaseSensitive == nil {
		caseSensitive = true
	} else {
		caseSensitive = *req.CaseSensitive
	}

	// 校验并展开参与关键词匹配的字段，缺省为全部可搜索字段
	requested := req.Fields
	if len(requested) == 0 {
		requested = make([]string, 0, len(cfg.Fields))
		for _, f := range cfg.Fields {
			requested = append(requested, f.ID)
		}
	}
	searchFields := make([]Field, 0, len(requested))
	seenFields := make(map[string]struct{}, len(requested))
	for _, id := range requested {
		f, ok := fieldsByID[id]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails("搜索字段不存在：" + id)
		}
		if _, duplicated := seenFields[id]; duplicated {
			continue
		}
		seenFields[id] = struct{}{}
		searchFields = append(searchFields, f)
	}

	var conditions []sq.Sqlizer
	trimmed := strings.TrimSpace(req.Query)
	if e := validateSearchQuery(trimmed, method); e != nil {
		return nil, e
	}

	// 关键词条件：各字段之间用 OR 连接；没有有效条件时整个关键词条件省略
	if trimmed != "" && len(searchFields) > 0 {
		orParts := make([]sq.Sqlizer, 0, len(searchFields))
		for _, f := range searchFields {
			if c := buildMatchCondition(f, trimmed, method, caseSensitive); c != nil {
				orParts = append(orParts, c)
			}
		}
		if len(orParts) > 0 {
			conditions = append(conditions, sq.Or(orParts))
		}
	}

	// 字段级条件与总关键词条件之间为 AND，匹配方法/大小写缺省沿用顶层设置。
	if len(req.FieldQueries) > MaxFieldQueries {
		return nil, errs.BadRequestError().AppendDetails("字段查询条件过多")
	}
	for _, fieldQuery := range req.FieldQueries {
		f, ok := fieldsByID[fieldQuery.Field]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails("搜索字段不存在：" + fieldQuery.Field)
		}

		query := strings.TrimSpace(fieldQuery.Query)
		if query == "" {
			continue
		}

		fieldMethod := method
		if fieldQuery.MatchMethod != nil {
			fieldMethod = *fieldQuery.MatchMethod
			if _, ok := allowedMatch[fieldMethod]; !ok {
				return nil, errs.BadRequestError().AppendDetails("匹配方法不受支持：" + string(fieldMethod))
			}
		}
		fieldCaseSensitive := caseSensitive
		if fieldQuery.CaseSensitive != nil {
			fieldCaseSensitive = *fieldQuery.CaseSensitive
		}

		if e := validateSearchQuery(query, fieldMethod); e != nil {
			return nil, e
		}
		if c := buildMatchCondition(f, query, fieldMethod, fieldCaseSensitive); c != nil {
			conditions = append(conditions, c)
		}
	}

	// 先校验请求中出现的标签 ID，再按配置顺序构建标签条件
	for tagID := range req.Tags {
		if _, ok := tagsByID[tagID]; !ok {
			return nil, errs.BadRequestError().AppendDetails("标签不存在：" + tagID)
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

	// 拼接调用方固定的附加条件（软删除过滤、应用隔离等）
	conditions = append(conditions, cfg.AdditionalWhere...)

	// 构造 COUNT 与数据查询骨架
	countB := psql.Select("COUNT(*)").From(cfg.Table)
	dataB := psql.Select("*").From(cfg.Table)
	if len(cfg.Columns) > 0 {
		dataB = psql.Select(cfg.Columns...).From(cfg.Table)
	}

	if len(conditions) > 0 {
		where := sq.And(conditions)
		countB = countB.Where(where)
		dataB = dataB.Where(where)
	}

	// 排序：显式排序字段优先；未指定时使用默认排序列。
	switch {
	case req.SortBy.Valid:
		f, ok := sortableByID[req.SortBy.String]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails("排序字段不存在：" + req.SortBy.String)
		}
		var dir string
		var order SortOrder
		if req.SortOrder != nil {
			order = *req.SortOrder
		} else {
			order = SortOrderAscending
		}
		switch order {
		case SortOrderAscending:
			dir = "ASC"
		case SortOrderDescending:
			dir = "DESC"
		default:
			return nil, errs.BadRequestError().AppendDetails("排序顺序不受支持：" + string(order))
		}
		dataB = dataB.OrderBy(fmt.Sprintf("%s %s", f.Column, dir))
		// 显式排序字段可能不唯一，追加默认排序列保证分页稳定。
		if cfg.DefaultSortColumn != "" && cfg.DefaultSortColumn != f.Column {
			dataB = dataB.OrderBy(cfg.DefaultSortColumn)
		}

	case cfg.DefaultSortColumn != "":
		dataB = dataB.OrderBy(cfg.DefaultSortColumn)
	}

	// 分页：未提供或非正数 limit 用 DefaultLimit，超过 MaxLimit 时截断；offset 仅取正值
	var limit int64
	if req.Limit.Valid {
		limit = req.Limit.Int64
	} else {
		limit = DefaultLimit
	}
	if limit <= 0 {
		limit = DefaultLimit
	} else if limit > MaxLimit {
		limit = MaxLimit
	}
	dataB = dataB.Limit(uint64(limit))
	if req.Offset.Valid && req.Offset.Int64 > 0 {
		dataB = dataB.Offset(uint64(req.Offset.Int64))
	}

	// 生成最终参数化 SQL
	countSQL, countArgs, e := countB.ToSql()
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to build search count query", "table", cfg.Table).AppendDetails("SQL 语句构建失败")
	}
	dataSQL, dataArgs, e := dataB.ToSql()
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to build search data query", "table", cfg.Table).AppendDetails("SQL 语句构建失败")
	}

	return &SearchQuery{
		Count: Query{SQL: countSQL, Args: countArgs},
		Data:  Query{SQL: dataSQL, Args: dataArgs},
	}, nil
}

func validateSearchQuery(query string, method MatchMethod) *errs.Error {
	if len([]rune(query)) > MaxQueryLength {
		return errs.BadRequestError().AppendDetails("搜索表达式过长")
	}
	if method == MatchMethodFuzzy && len(strings.Fields(query)) > MaxFuzzyWords {
		return errs.BadRequestError().AppendDetails("搜索词过多")
	}
	return nil
}

// buildMatchCondition 为单个字段与关键词构建匹配条件，方法不受支持时返回 nil。
// Numeric 字段先转 ::text 再匹配；区分大小写时用 LIKE/~，否则用 ILIKE/~*。
// 注意：这里用字符串字面量比较 MatchMethod，修改 ENUM 声明时需同步。
func buildMatchCondition(f Field, query string, method MatchMethod, caseSensitive bool) sq.Sqlizer {
	col := f.Column
	if f.Numeric {
		col = f.Column + "::text"
	}

	likeOp := "ILIKE"
	reOp := "~*"
	if caseSensitive {
		likeOp = "LIKE"
		reOp = "~"
	}

	switch string(method) {
	case "exact":
		// 等值匹配；不区分大小写时两边转小写比较
		if caseSensitive {
			return sq.Eq{col: query}
		}
		return sq.Expr(fmt.Sprintf("lower(%s) = lower(?)", col), query)

	case "contains":
		// 包含匹配
		return sq.Expr(
			fmt.Sprintf("%s %s ?", col, likeOp),
			"%"+escapeLike(query)+"%",
		)

	case "prefix":
		// 前缀匹配
		return sq.Expr(
			fmt.Sprintf("%s %s ?", col, likeOp),
			escapeLike(query)+"%",
		)

	case "suffix":
		// 后缀匹配
		return sq.Expr(
			fmt.Sprintf("%s %s ?", col, likeOp),
			"%"+escapeLike(query),
		)

	case "fuzzy":
		// 按空白分词，每个词都要包含（AND）
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
		// 正则匹配
		return sq.Expr(fmt.Sprintf("%s %s ?", col, reOp), query)
	}
	return nil
}

// escapeLike 转义 LIKE 模式中的反斜杠、% 与 _，避免用户输入被当作通配符。
func escapeLike(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`%`, `\%`,
		`_`, `\_`,
	)
	return r.Replace(s)
}

// buildTagCondition 把标签选择转换为列的 IN / NOT IN 条件。
// ValueMap 是「列值 -> 标签值」，这里先反转出「标签值 -> 列值列表」再展开为 = ANY(...)。
// include 与 exclude 同时存在时用 AND 连接；两者都为空时返回 nil（不产生条件）。
func buildTagCondition(tag Tag, sel TagSelection) (sq.Sqlizer, *errs.Error) {
	reverse := make(map[string][]string, len(tag.ValueMap))
	for colVal, tagVal := range tag.ValueMap {
		reverse[tagVal] = append(reverse[tagVal], colVal)
	}

	var includeVals []string
	for _, id := range sel.Include {
		vals, ok := reverse[id]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails(fmt.Sprintf("标签不存在：%s.%s", tag.ID, id))
		}
		includeVals = append(includeVals, vals...)
	}

	var excludeVals []string
	for _, id := range sel.Exclude {
		vals, ok := reverse[id]
		if !ok {
			return nil, errs.BadRequestError().AppendDetails(fmt.Sprintf("标签不存在：%s.%s", tag.ID, id))
		}
		excludeVals = append(excludeVals, vals...)
	}

	var parts []sq.Sqlizer
	if len(includeVals) > 0 {
		parts = append(parts, sq.Expr(fmt.Sprintf("%s::text = ANY(?)", tag.Column), includeVals))
	}
	if len(excludeVals) > 0 {
		parts = append(parts, sq.Expr(
			fmt.Sprintf("(%s IS NULL OR NOT (%s::text = ANY(?)))", tag.Column, tag.Column),
			excludeVals,
		))
	}
	if len(parts) == 0 {
		return nil, nil
	}
	return sq.And(parts), nil
}
