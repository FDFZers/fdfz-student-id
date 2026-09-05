package sse

import (
	"io"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ENUM(update, delete)
type HubMessageType int

type HubMessage[T any] struct {
	Data T
	Type HubMessageType
}

type sseConn struct {
	cancel chan struct{}
}

type Hub[T any] struct {
	mu      sync.RWMutex
	clients map[chan HubMessage[T]]struct{}

	conns  map[*sseConn]struct{}
	closed bool
}

func NewHub[T any]() *Hub[T] {
	return &Hub[T]{
		clients: make(map[chan HubMessage[T]]struct{}),
		conns:   make(map[*sseConn]struct{}),
	}
}

func (h *Hub[T]) Subscribe() chan HubMessage[T] {
	ch := make(chan HubMessage[T], 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub[T]) Unsubscribe(ch chan HubMessage[T]) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *Hub[T]) publish(msg HubMessage[T]) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *Hub[T]) PublishUpdate(data T) {
	h.publish(HubMessage[T]{Data: data, Type: HubMessageTypeUpdate})
}

func (h *Hub[T]) PublishDelete(data T) {
	h.publish(HubMessage[T]{Data: data, Type: HubMessageTypeDelete})
}

func (h *Hub[T]) addConn(conn *sseConn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.conns[conn] = struct{}{}
	return true
}

func (h *Hub[T]) removeConn(conn *sseConn) {
	h.mu.Lock()
	delete(h.conns, conn)
	h.mu.Unlock()
}

func (h *Hub[T]) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for conn := range h.conns {
		close(conn.cancel)
		delete(h.conns, conn)
	}
}

func (h *Hub[T]) HandleSSE(c *gin.Context, filterFn func(data T) bool, expiresAt func(data T) *time.Time) {
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	conn := &sseConn{cancel: make(chan struct{})}
	if !h.addConn(conn) {
		return
	}
	defer h.removeConn(conn)

	var timerC <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	c.Stream(func(w io.Writer) bool {
		select {
		case msg, ok := <-ch:
			if !ok {
				return false
			}
			if !filterFn(msg.Data) {
				return true
			}
			switch {
			case msg.Type == HubMessageTypeDelete:
				return false
			case msg.Type == HubMessageTypeUpdate:
				if expiresAt != nil {
					exp := expiresAt(msg.Data)
					if exp == nil {
						// nil 表示不设置过期
						timerC = nil
						if timer != nil {
							timer.Stop()
							timer = nil
						}
					} else {
						d := time.Until(*exp)
						if d <= 0 {
							return false
						}
						if timer != nil {
							timer.Stop()
						}
						timer = time.NewTimer(d)
						timerC = timer.C
					}
				}
				c.SSEvent("update", msg.Data)
				return true
			}
			return false
		case <-timerC:
			c.SSEvent("expired", "")
			return false
		case <-conn.cancel:
			c.SSEvent("server_closed", "")
			return false
		}
	})
}

func SetSSEHeaders(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.WriteHeaderNow()
	c.SSEvent("connected", "")
	c.Writer.Flush()
}
