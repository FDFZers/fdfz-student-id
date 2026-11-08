package handling

import (
	"io"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

// bodyLimitReaderKey 是 bodyLimitReader 在 gin.Context 中的存放键。
const bodyLimitReaderKey = "handling_body_limit_reader"

// BodyLimitReader 是可动态调整上限的请求体读取器。
// 全局中间件以默认上限（1 MiB）安装它；显式挂载的 middleware.LimitSize(max) 可在读取请求体之前
// 通过 SetLimit 重新设置上限，从而支持「全局 1 MiB，除非路由重新设置」的语义。
type BodyLimitReader struct {
	mu       sync.Mutex
	body     io.ReadCloser
	max      int64
	read     int64
	exceeded bool
}

// InstallBodyLimitReader 用给定上限包装请求体并安装到 gin.Context；已安装时改为调整上限。
func InstallBodyLimitReader(c *gin.Context, maxBytes int64) *BodyLimitReader {
	if r, ok := GetBodyLimitReader(c); ok {
		r.SetLimit(maxBytes)
		return r
	}
	r := &BodyLimitReader{body: c.Request.Body, max: maxBytes}
	c.Request.Body = r
	c.Set(bodyLimitReaderKey, r)
	return r
}

// GetBodyLimitReader 返回当前请求已安装的读取器。
func GetBodyLimitReader(c *gin.Context) (*BodyLimitReader, bool) {
	value, ok := c.Get(bodyLimitReaderKey)
	if !ok {
		return nil, false
	}
	r, ok := value.(*BodyLimitReader)
	return r, ok
}

// SetLimit 调整上限；只允许在尚未读取请求体时调整，读取开始后忽略。
func (r *BodyLimitReader) SetLimit(maxBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.read == 0 && !r.exceeded {
		r.max = maxBytes
	}
}

// Limit 返回当前上限。
func (r *BodyLimitReader) Limit() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}

// Exceeded 返回本请求是否已因请求体超限而失败。
func (r *BodyLimitReader) Exceeded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exceeded
}

// BodyLimitExceeded 判断本次请求是否因请求体超限而失败，供 handling.Wrap 统一映射为 413。
func BodyLimitExceeded(c *gin.Context) bool {
	r, ok := GetBodyLimitReader(c)
	return ok && r.Exceeded()
}

// Read 实现 io.Reader：超过上限时返回 *http.MaxBytesError 并标记 exceeded。
func (r *BodyLimitReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.exceeded {
		limit := r.max
		r.mu.Unlock()
		return 0, &http.MaxBytesError{Limit: limit}
	}
	remaining := r.max - r.read
	if remaining <= 0 {
		r.exceeded = true
		limit := r.max
		r.mu.Unlock()
		return 0, &http.MaxBytesError{Limit: limit}
	}
	// 多读 1 字节用于检测超限：上限内的数据正常返回，超限后下一次 Read 报错。
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	r.mu.Unlock()

	n, err := r.body.Read(p)

	r.mu.Lock()
	r.read += int64(n)
	if r.read > r.max {
		r.exceeded = true
		limit := r.max
		r.mu.Unlock()
		return n, &http.MaxBytesError{Limit: limit}
	}
	r.mu.Unlock()
	return n, err
}

// Close 关闭底层请求体。
func (r *BodyLimitReader) Close() error {
	return r.body.Close()
}
