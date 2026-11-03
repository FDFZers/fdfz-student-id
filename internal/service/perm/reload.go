package perm

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"fdfz-student-id/internal/errs"
)

const DefaultReloadThrottle = time.Second

type ReloadStatus struct {
	LastAttemptAt time.Time `json:"last_attempt_at"`
	LastSuccessAt time.Time `json:"last_success_at"`
	LastError     string    `json:"last_error,omitempty"`
	Pending       bool      `json:"pending"`
	Version       uint64    `json:"version"`
}

type Reloader struct {
	load     func(context.Context) *errs.Error
	throttle time.Duration

	notify chan struct{}

	reloadMu sync.Mutex

	mu     sync.Mutex
	status ReloadStatus

	startOnce sync.Once
}

func NewReloader(loader func(context.Context) *errs.Error, throttle time.Duration) *Reloader {
	if throttle <= 0 {
		throttle = DefaultReloadThrottle
	}
	return &Reloader{
		load:     loader,
		throttle: throttle,
		notify:   make(chan struct{}, 1),
	}
}

func (r *Reloader) Start(ctx context.Context) {
	r.startOnce.Do(func() {
		go r.loop(ctx)
		slog.Info("Permission catalog auto reload started", "throttle", r.throttle.String())
	})
}

func (r *Reloader) Notify() {
	r.mu.Lock()
	r.status.Pending = true
	r.mu.Unlock()

	select {
	case r.notify <- struct{}{}:
	default:
	}
}

func (r *Reloader) ReloadNow(ctx context.Context) *errs.Error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	r.mu.Lock()
	r.status.LastAttemptAt = time.Now()
	r.mu.Unlock()

	err := r.load(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.status.Pending = false
	if err != nil {
		r.status.LastError = reloadErrorText(err)
		slog.Warn("Failed to reload permission catalog", "error", r.status.LastError)
		return err
	}
	r.status.LastError = ""
	r.status.LastSuccessAt = time.Now()
	r.status.Version++
	return nil
}

func (r *Reloader) Status() ReloadStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

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

func (r *Reloader) loop(ctx context.Context) {
	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return

		case <-r.notify:
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
			timer = nil
			timerC = nil

			reloadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = r.ReloadNow(reloadCtx)
			cancel()
		}
	}
}

var defaultReloader = NewReloader(Load, DefaultReloadThrottle)

func StartAutoReload(ctx context.Context, throttle time.Duration) {
	if throttle > 0 {
		defaultReloader.mu.Lock()
		defaultReloader.throttle = throttle
		defaultReloader.mu.Unlock()
	}
	defaultReloader.Start(ctx)
}

func NotifyReload() {
	defaultReloader.Notify()
}

func ReloadNow(ctx context.Context) *errs.Error {
	return defaultReloader.ReloadNow(ctx)
}

func GetReloadStatus() ReloadStatus {
	return defaultReloader.Status()
}
