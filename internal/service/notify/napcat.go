package notify

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fdfz-student-id/internal/cfg"
)

const (
	defaultHistoryCount = 20              // 默认拉取的历史消息条数
	maxHistoryCount     = 50              // 单次拉取上限，超过时回退为默认条数
	httpTimeout         = 8 * time.Second // 单次 NapCat 请求超时
	maxResponseBody     = 4 << 20         // 响应体读取上限（4 MiB），避免异常响应占满内存
)

// OBMessage 是从 NapCat 消息历史中提取出的单条私聊消息。
type OBMessage struct {
	Time     int64  // 发送时间（Unix 秒）
	SenderQQ int64  // 发送者 QQ 号
	Text     string // 文本内容，仅拼接 text 类型的消息段
}

// apiResponse 是 OneBot 11 的通用响应包装。
type apiResponse struct {
	Status  string         `json:"status"`  // ok 表示接口调用成功
	RetCode int            `json:"retcode"` // 0 表示成功，非 0 为错误码
	Data    jsontext.Value `json:"data"`    // 各接口的返回数据
	Message string         `json:"message"` // 错误描述
	Wording string         `json:"wording"` // 错误补充说明
}

// endpointURL 拼接 NapCat 基础地址与 API 路径，去掉基础地址末尾多余的 /。
func endpointURL(path string) string {
	return strings.TrimRight(strings.TrimSpace(cfg.C.NapCatEndpoint), "/") + path
}

// post 向 NapCat 发送 JSON 请求并解析 OneBot 11 响应。
// 注意：非 2xx 状态码、status 非 ok 或 retcode 非 0 都会返回错误；配置 NAPCAT_TOKEN 时自动带 Bearer 认证。
func post(ctx context.Context, path string, payload any) (jsontext.Value, error) {
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

	// 每次请求单独创建客户端，超时由 httpTimeout 控制
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

// GetFriendMsgHistory 拉取指定 QQ 好友最近 count 条私聊消息（机器人视角）。
// count 非正数或超过上限时回退为默认条数；单条消息解析失败会被跳过而不是返回错误。
func GetFriendMsgHistory(ctx context.Context, qq string, count int) ([]OBMessage, error) {
	if count <= 0 || count > maxHistoryCount {
		count = defaultHistoryCount
	}
	// OneBot 11 的 user_id 是数字类型。
	userID, err := strconv.ParseInt(qq, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("qq: invalid qq number %q: %w", qq, err)
	}
	data, err := post(ctx, "/get_friend_msg_history", map[string]any{
		"user_id": userID,
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
		Messages []jsontext.Value `json:"messages"`
	}
	var items []jsontext.Value
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Messages != nil {
		items = wrapped.Messages
	} else if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("qq: unexpected message history shape: %w", err)
	}

	// 逐条解析，畸形消息跳过
	messages := make([]OBMessage, 0, len(items))
	for _, item := range items {
		msg, err := parseMessage(item)
		if err != nil {
			continue
		}
		messages = append(messages, msg)
	}
	return messages, nil
}

// SendPrivateMessage 向指定 QQ 号发送私聊文本消息，用于账号安全通知等主动提醒。
// 注意：正文以 text 消息段发送，避免邮箱等动态内容被当作 CQ 码解析。
func SendPrivateMessage(ctx context.Context, qq int64, message string) error {
	_, err := post(ctx, "/send_private_msg", map[string]any{
		"user_id": qq,
		"message": []map[string]any{
			{
				"type": "text",
				"data": map[string]string{"text": message},
			},
		},
	})
	return err
}

// oneBotMessage 是 OneBot 11 消息对象中本包关心的字段。
type oneBotMessage struct {
	Time    int64  `json:"time"`
	UserID  int64  `json:"user_id"`
	RawText string `json:"raw_message"`
	Sender  struct {
		UserID int64 `json:"user_id"`
	} `json:"sender"`
	Message jsontext.Value `json:"message"`
}

// parseMessage 把 OneBot 消息对象转换为 OBMessage，优先取消息段文本与 sender.user_id，缺失时回退。
func parseMessage(raw jsontext.Value) (OBMessage, error) {
	var m oneBotMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return OBMessage{}, err
	}
	sender := m.Sender.UserID
	if sender == 0 {
		sender = m.UserID
	}
	text := extractText(m.Message)
	if text == "" {
		text = m.RawText
	}
	return OBMessage{Time: m.Time, SenderQQ: sender, Text: text}, nil
}

// extractText 提取纯文本：兼容 OneBot 的纯字符串与消息段数组两种 message 形状，只拼接 text 段。
func extractText(raw jsontext.Value) string {
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
