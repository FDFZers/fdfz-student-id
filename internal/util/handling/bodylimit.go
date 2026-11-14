package handling

import (
	"io"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

const bodyLimitReaderKey = "handling_body_limit_reader"

// BodyLimitReader 是可动态调整上限的请求体读取器：全局默认 1 MiB，路由可在读取前覆盖。
type BodyLimitReader struct {
	mu       sync.Mutex
	body     io.ReadCloser
	max      int64
	read     int64
	exceeded bool
}

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

func GetBodyLimitReader(c *gin.Context) (*BodyLimitReader, bool) {
	value, ok := c.Get(bodyLimitReaderKey)
	if !ok {
		return nil, false
	}
	r, ok := value.(*BodyLimitReader)
	return r, ok
}

// SetLimit 在读取开始后调用会被忽略。
func (r *BodyLimitReader) SetLimit(maxBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.read == 0 && !r.exceeded {
		r.max = maxBytes
	}
}

func (r *BodyLimitReader) Limit() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}

func (r *BodyLimitReader) Exceeded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exceeded
}

// BodyLimitExceeded 供 Wrap 统一映射为 413。
func BodyLimitExceeded(c *gin.Context) bool {
	r, ok := GetBodyLimitReader(c)
	return ok && r.Exceeded()
}

// Read 超限时返回 *http.MaxBytesError。
// 恰好读完 max 字节不算超限，探测到后续数据才判定超限。
func (r *BodyLimitReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.exceeded {
		limit := r.max
		r.mu.Unlock()
		return 0, &http.MaxBytesError{Limit: limit}
	}
	remaining := r.max - r.read
	r.mu.Unlock()

	if remaining <= 0 {
		var probe [1]byte
		n, err := r.body.Read(probe[:])
		if n > 0 {
			r.mu.Lock()
			r.exceeded = true
			limit := r.max
			r.mu.Unlock()
			return 0, &http.MaxBytesError{Limit: limit}
		}
		return 0, err
	}

	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.body.Read(p)

	r.mu.Lock()
	r.read += int64(n)
	exceeded := r.read > r.max
	limit := r.max
	r.mu.Unlock()
	if exceeded {
		return n, &http.MaxBytesError{Limit: limit}
	}
	return n, err
}

func (r *BodyLimitReader) Close() error {
	return r.body.Close()
}
