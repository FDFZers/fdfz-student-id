// Package qq 封装 NapCat（OneBot 11 HTTP）接口，用于拉取私聊消息与发送消息。
package qq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fdfz-student-id/internal/cfg"
)

const (
	defaultHistoryCount = 20
	maxHistoryCount     = 50
	httpTimeout         = 8 * time.Second
	maxResponseBody     = 4 << 20
)

type Message struct {
	Time     int64
	SenderQQ int64
	Text     string
}

type apiResponse struct {
	Status  string          `json:"status"`
	RetCode int             `json:"retcode"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
	Wording string          `json:"wording"`
}

func endpointURL(path string) string {
	return strings.TrimRight(strings.TrimSpace(cfg.C.NapCatEndpoint), "/") + path
}

func post(ctx context.Context, path string, payload any) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("qq: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL(path), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("qq: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.C.NapCatToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.C.NapCatToken)
	}

	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("qq: request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("qq: read response: %w", err)
	}

	var api apiResponse
	if err := json.Unmarshal(raw, &api); err != nil {
		return nil, fmt.Errorf("qq: decode response (http %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("qq: http %d: %s", resp.StatusCode, api.Message)
	}
	if api.Status != "" && api.Status != "ok" {
		return nil, fmt.Errorf("qq: status %s: %s", api.Status, api.Wording)
	}
	if api.RetCode != 0 {
		return nil, fmt.Errorf("qq: retcode %d: %s", api.RetCode, api.Message)
	}
	return api.Data, nil
}

func GetFriendMsgHistory(ctx context.Context, qq string, count int) ([]Message, error) {
	if count <= 0 || count > maxHistoryCount {
		count = defaultHistoryCount
	}
	data, err := post(ctx, "/get_friend_msg_history", map[string]any{
		"user_id": qq,
		"count":   count,
	})
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}

	// NapCat/go-cqhttp 的 data 既可能是 {"messages":[...]}，也可能直接是数组
	var wrapped struct {
		Messages []json.RawMessage `json:"messages"`
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Messages != nil {
		items = wrapped.Messages
	} else if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("qq: unexpected message history shape: %w", err)
	}

	messages := make([]Message, 0, len(items))
	for _, item := range items {
		msg, err := parseMessage(item)
		if err != nil {
			continue
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

func SendPrivateMessage(ctx context.Context, qq int64, message string) error {
	_, err := post(ctx, "/send_private_msg", map[string]any{
		"user_id": qq,
		"message": message,
	})
	return err
}

type oneBotMessage struct {
	Time    int64  `json:"time"`
	UserID  int64  `json:"user_id"`
	RawText string `json:"raw_message"`
	Sender  struct {
		UserID int64 `json:"user_id"`
	} `json:"sender"`
	Message json.RawMessage `json:"message"`
}

func parseMessage(raw json.RawMessage) (Message, error) {
	var m oneBotMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return Message{}, err
	}
	sender := m.Sender.UserID
	if sender == 0 {
		sender = m.UserID
	}
	text := extractText(m.Message)
	if text == "" {
		text = m.RawText
	}
	return Message{Time: m.Time, SenderQQ: sender, Text: text}, nil
}

func extractText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var plain string
	if err := json.Unmarshal(raw, &plain); err == nil {
		return plain
	}
	var segments []struct {
		Type string `json:"type"`
		Data struct {
			Text string `json:"text"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &segments); err != nil {
		return ""
	}
	var b strings.Builder
	for _, seg := range segments {
		if seg.Type == "text" {
			b.WriteString(seg.Data.Text)
		}
	}
	return b.String()
}
