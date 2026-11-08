package search

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

// ValueMapOf 把取值列表构造成「值 -> 值」的恒等映射，用于标签定义。
func ValueMapOf(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value] = value
	}
	return result
}

// NormalizePagination 规范化分页参数：limit 缺省或非正数取 DefaultLimit、超上限取 MaxLimit；offset 负数取 0。
func NormalizePagination(limit, offset int32) (int32, int32) {
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// ParseQueryPagination 从 query 参数解析 limit 与 offset。
// 注意：非法数字会被静默忽略并回退默认值，不返回参数错误。
func ParseQueryPagination(c *gin.Context) (limit, offset int32) {
	limit = DefaultLimit
	if raw := c.Query("limit"); raw != "" {
		if i, err := strconv.ParseInt(raw, 10, 32); err == nil {
			limit = int32(i)
		}
	}

	offset = 0
	if raw := c.Query("offset"); raw != "" {
		if i, err := strconv.ParseInt(raw, 10, 32); err == nil {
			offset = int32(i)
		}
	}

	return NormalizePagination(limit, offset)
}
