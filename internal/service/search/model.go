//go:generate go tool go-enum --names --values --marshal --sql
package search

import (
	"github.com/Masterminds/squirrel"
	"github.com/guregu/null/v6"
)

// ENUM(contains, exact, prefix, suffix, fuzzy, regex)
// MatchMethod 是搜索字段的匹配方式，决定生成的 SQL 条件运算符。
type MatchMethod string

// ENUM(ascending = "asc", descending = "desc")
// SortOrder 是排序方向：ascending 升序、descending 降序。
type SortOrder string

// SearchInfo 是对外暴露的搜索元信息，告诉前端有哪些字段、匹配方式、排序字段与标签可选。
type SearchInfo struct {
	Fields         []string            `json:"fields"`          // 可搜索字段 ID 列表
	MatchMethods   []MatchMethod       `json:"match_methods"`   // 支持的匹配方法
	SortableFields []string            `json:"sortable_fields"` // 可排序字段 ID 列表
	Tags           map[string][]string `json:"tags"`            // 标签 ID -> 可选标签值
}

// SearchRequest 是搜索查询请求体，各白名单校验失败时返回 bad_request。
type SearchRequest struct {
	Query         string                  `json:"query"`          // 搜索关键词，空串表示不带关键词条件
	Limit         null.Int64              `json:"limit"`          // 分页大小，缺省用 DefaultLimit（显式 <=0 视为超限）
	Offset        null.Int64              `json:"offset"`         // 偏移量，缺省或负数按 0 处理
	Fields        []string                `json:"fields"`         // 参与关键词匹配的字段，缺省为全部可搜索字段
	SortBy        null.String             `json:"sort_by"`        // 排序字段，为空表示按相关度（当前实现不排序）
	SortOrder     *SortOrder              `json:"sort_order"`     // 排序方向，缺省 ascending
	MatchMethod   *MatchMethod            `json:"match_method"`   // 匹配方法，缺省 contains
	CaseSensitive *bool                   `json:"case_sensitive"` // 是否区分大小写，缺省 true
	Tags          map[string]TagSelection `json:"tags"`           // 标签过滤，key 为标签 ID
}

// SearchResponse 是搜索结果的元信息快照。
// 存疑：当前仓库内没有被任何处理器使用，接口实际返回由处理器自行组装。
type SearchResponse struct {
	Total          int                 `json:"total"`
	Fields         []string            `json:"fields"`
	MatchMethods   []MatchMethod       `json:"match_methods"`
	SortableFields []string            `json:"sortable_fields"`
	Tags           map[string][]string `json:"tags"`
}

// TagSelection 是单个标签的过滤条件：include 要求命中任一值，exclude 要求都不命中。
type TagSelection struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// Field 描述一个可搜索或可排序字段。
type Field struct {
	ID      string // 对外暴露的字段名
	Column  string // 实际 SQL 列（可带表别名，如 pd.value）
	Numeric bool   // 是否为数值列：匹配时按 ::text 转换后比较
}

// Tag 描述一个标签维度：把数据库列值映射为对外标签值。
type Tag struct {
	ID       string            // 对外暴露的标签名
	Column   string            // 实际 SQL 列（可带表别名）
	ValueMap map[string]string // 数据库列值 -> 对外标签值 ID
}

// SearchConfig 是某类资源搜索的静态配置，由各处理器在包级变量中定义。
type SearchConfig struct {
	Table             string             // FROM 子句，可包含 JOIN，如 "permission_defs pd JOIN oauth_apps a ON ..."
	Item              string             // 资源中文名，用于 PostgreSQL 错误文案
	Fields            []Field            // 关键词可匹配字段白名单
	MatchMethods      []MatchMethod      // 允许的匹配方法白名单
	SortableFields    []Field            // 允许的排序字段白名单
	Tags              []Tag              // 标签过滤定义
	Columns           []string           // 数据查询 SELECT 列表，为空时 SELECT *
	AdditionalWhere   []squirrel.Sqlizer // 固定附加的 WHERE 条件（软删除过滤、应用隔离等）
	DefaultSortColumn string             // query 为空且未指定排序时的默认 ORDER BY 列，空串表示不排序
}

// Query 是一条参数化 SQL 及其参数。
type Query struct {
	SQL  string
	Args []any
}

// SearchQuery 是搜索产生的两条 SQL：计数查询与数据查询。
type SearchQuery struct {
	Count Query
	Data  Query
}

// SearchResult 是搜索执行结果：命中总数与当前页数据。
type SearchResult[T any] struct {
	Count int32
	Data  []*T
}
