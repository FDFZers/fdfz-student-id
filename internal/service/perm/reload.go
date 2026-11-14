package perm

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"fdfz-student-id/internal/errs"
)

// DefaultReloadThrottle 是自动重载的默认最小间隔：两次重载尝试之间至少间隔该时长。
const DefaultReloadThrottle = time.Second

// DefaultAutoReloadInterval 是周期性兜底重载的间隔：Notify 只在进程内有效，多副本部署靠它最终一致。
const DefaultAutoReloadInterval = 30 * time.Second

// ReloadStatus 是权限目录重载器的状态快照，通过 GET /permissions/reload/status 暴露。
type ReloadStatus struct {
	// LastAttemptAt 是最近一次重载尝试的时间（无论成功与否）。
	LastAttemptAt time.Time `json:"last_attempt_at"`
	// LastSuccessAt 是最近一次成功重载的时间。
	LastSuccessAt time.Time `json:"last_success_at"`
	// LastError 是最近一次失败的错误摘要，成功后清空。
	LastError string `json:"last_error,omitempty"`
	// Pending 表示是否有尚未处理的变更通知。
	Pending bool `json:"pending"`
	// Version 是成功重载次数，每次成功后自增。
	Version uint64 `json:"version"`
}

// Reloader 以节流方式异步重载权限目录：Notify 只投递信号，真正的加载在后台 goroutine 中串行执行。
type Reloader struct {
	// load 是实际加载函数；生产环境为 Load。
	load func(context.Context) *errs.Error
	// throttle 是两次重载尝试之间的最小间隔。
	throttle time.Duration
	interval time.Duration

	// notify 为容量 1 的信号通道，重复 Notify 会合并成一次重载。
	notify chan struct{}

	// reloadMu 串行化 ReloadNow，避免并发加载覆盖状态。
	reloadMu sync.Mutex

	// mu 保护 status 的读写。
	mu     sync.Mutex
	status ReloadStatus

	// startOnce 保证 Start 只启动一个后台 goroutine。
	startOnce sync.Once
}

// NewReloader 创建重载器；throttle <= 0 时回退为 DefaultReloadThrottle。
func NewReloader(loader func(context.Context) *errs.Error, throttle time.Duration) *Reloader {
	if throttle <= 0 {
		throttle = DefaultReloadThrottle
	}
	return &Reloader{
		load:     loader,
		throttle: throttle,
		interval: DefaultAutoReloadInterval,
		notify:   make(chan struct{}, 1),
	}
}

// Start 启动后台自动重载 goroutine；重复调用只有首次生效，ctx 取消后 goroutine 退出。
func (r *Reloader) Start(ctx context.Context) {
	r.startOnce.Do(func() {
		go r.loop(ctx)
		slog.Info("Permission catalog auto reload started", "throttle", r.throttle.String())
	})
}

// Notify 标记有变更待重载并唤醒后台 goroutine；非阻塞，信号会自动合并。
func (r *Reloader) Notify() {
	r.mu.Lock()
	r.status.Pending = true
	r.mu.Unlock()

	r.wake()
}

// wake 只投递唤醒信号，不改变 Pending 状态。
func (r *Reloader) wake() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// ReloadNow 立即同步重载一次（由 reloadMu 串行化），并更新状态；失败时返回加载错误。
// 注意：加载失败不会清空旧目录快照，鉴权继续使用上一次成功加载的数据。
func (r *Reloader) ReloadNow(ctx context.Context) *errs.Error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	r.mu.Lock()
	r.status.LastAttemptAt = time.Now()
	r.mu.Unlock()

	err := r.load(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil {
		r.status.LastError = reloadErrorText(err)
		slog.Warn("Failed to reload permission catalog", "error", r.status.LastError)
		return err
	}
	r.status.Pending = false
	r.status.LastError = ""
	r.status.LastSuccessAt = time.Now()
	r.status.Version++
	return nil
}

// Status 返回当前重载状态的副本，供 HTTP API 输出。
func (r *Reloader) Status() ReloadStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// reloadErrorText 把错误 id 与各条 details 拼成单行文本，用于状态展示与日志。
func reloadErrorText(err *errs.Error) string {
	if err == nil {
		return ""
	}
	var text strings.Builder
	text.WriteString(err.Info.Error)
	for _, detail := range err.Info.Details {
		text.WriteString(": " + detail)
	}
	return text.String()
}

// loop 是自动重载循环：收到变更通知后按节流间隔安排一次重载，单次加载超时 10 秒。
func (r *Reloader) loop(ctx context.Context) {
	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return

		case <-ticker.C:
			r.wake()

		case <-r.notify:
			// 已有待触发的定时器时不再重复安排，信号自然合并
			if timer != nil {
				continue
			}
			delay := time.Duration(0)
			r.mu.Lock()
			if !r.status.LastAttemptAt.IsZero() {
				delay = r.throttle - time.Since(r.status.LastAttemptAt)
			}
			r.mu.Unlock()
			if delay < 0 {
				delay = 0
			}
			timer = time.NewTimer(delay)
			timerC = timer.C

		case <-timerC:
			// 定时器到期：执行一次重载
			timer = nil
			timerC = nil

			reloadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := r.ReloadNow(reloadCtx)
			cancel()
			if err != nil {
				// 加载失败时重新投递通知，在节流间隔后重试。
				r.Notify()
			}
		}
	}
}

// defaultReloader 是进程级默认重载器，HTTP API 与各业务服务通过下面的包级函数操作它。
var defaultReloader = NewReloader(Load, DefaultReloadThrottle)

// StartAutoReload 用给定节流间隔（> 0 时）配置默认重载器并启动自动重载。
func StartAutoReload(ctx context.Context, throttle time.Duration) {
	if throttle > 0 {
		defaultReloader.mu.Lock()
		defaultReloader.throttle = throttle
		defaultReloader.mu.Unlock()
	}
	defaultReloader.Start(ctx)
}

// NotifyReload 通知默认重载器权限数据有变更，通常在写入权限定义/继承关系后调用。
func NotifyReload() {
	defaultReloader.Notify()
}

// ReloadNow 立即重载默认重载器，HTTP 手动重载入口与启动初始化都走这里。
func ReloadNow(ctx context.Context) *errs.Error {
	return defaultReloader.ReloadNow(ctx)
}

// GetReloadStatus 返回默认重载器的当前状态。
func GetReloadStatus() ReloadStatus {
	return defaultReloader.Status()
}
