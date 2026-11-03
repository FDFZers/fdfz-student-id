package search

import (
	"strconv"

	"github.com/gin-gonic/gin"
)

func ValueMapOf(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value] = value
	}
	return result
}

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
