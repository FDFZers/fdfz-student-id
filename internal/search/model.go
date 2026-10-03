//go:generate go tool go-enum --names --values --marshal --sql
package search

import "github.com/guregu/null/v6"

// ENUM(contains, exact, prefix, suffix, fuzzy, regex)
type MatchMethod string

// ENUM(ascending = "asc", descending = "desc")
type SortOrder string

type SearchInfo struct {
	Fields         []string            `json:"fields"`
	MatchMethods   []MatchMethod       `json:"match_methods"`
	SortableFields []string            `json:"sortable_fields"`
	Tags           map[string][]string `json:"tags"`
}

type SearchRequest struct {
	Query         string                  `json:"query"`
	Limit         int                     `json:"limit"`
	Offset        int                     `json:"offset"`
	Fields        []string                `json:"fields"`
	SortBy        null.String             `json:"sort_by"` // null -> relevance
	SortOrder     SortOrder               `json:"sort_order"`
	MatchMethod   MatchMethod             `json:"match_method"`
	CaseSensitive bool                    `json:"case_sensitive"`
	Tags          map[string]TagSelection `json:"tags"`
}

type SearchResponse struct {
	Total          int                 `json:"total"`
	Fields         []string            `json:"fields"`
	MatchMethods   []MatchMethod       `json:"match_methods"`
	SortableFields []string            `json:"sortable_fields"`
	Tags           map[string][]string `json:"tags"`
}

type TagSelection struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

type Field struct {
	ID     string
	Column string
}

type Tag struct {
	ID       string
	Column   string
	ValueMap map[string]string // column value -> tag value id
}

type SearchConfig struct {
	Table             string
	Item              string
	Fields            []Field
	MatchMethods      []MatchMethod
	SortableFields    []Field
	Tags              []Tag
	DefaultSortColumn string // query is empty && sort is null
}

type Query struct {
	SQL  string
	Args []any
}

type SearchQuery struct {
	Count Query
	Data  Query
}

type SearchResult[T any] struct {
	Count int32
	Data  []*T
}
