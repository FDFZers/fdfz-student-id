package oauth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"time"

	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/util/crypto"

	"github.com/redis/go-redis/v9"
)

func authCodeCacheKey(codeHash string) string {
	return "student_id:oauth:code:" + codeHash
}

func deviceCodeCacheKey(deviceCodeHash string) string {
	return "student_id:oauth:device:code:" + deviceCodeHash
}

func deviceUserCodeCacheKey(userCode string) string {
	return "student_id:oauth:device:user:" + userCode
}

func consentRequestCacheKey(id string) string {
	return "student_id:oauth:consent:" + id
}

func ttlSeconds(ttl time.Duration) int64 {
	seconds := int64((ttl + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

// ---------------------------------------------------------------------------
// 授权码
// ---------------------------------------------------------------------------

type authorizationCode struct {
	AppID               int64     `json:"app_id"`
	AuthID              int64     `json:"auth_id"`
	UserID              int64     `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	RedirectURIProvided bool      `json:"redirect_uri_provided"`
	CodeChallenge       string    `json:"code_challenge"`
	ExpiresAt           time.Time `json:"expires_at"`
}

var getDelScript = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('DEL', KEYS[1])
end
return value
`)

func storeAuthorizationCode(ctx context.Context, record *authorizationCode) (string, *errs.Error) {
	code, err := crypto.GenerateCode(64, crypto.TokenCharset)
	if err != nil {
		return "", errs.CreateAndLogInternalError(err, "Failed to generate oauth authorization code").AppendDetails("授权码生成失败")
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return "", errs.CreateAndLogInternalError(err, "Failed to marshal oauth authorization code").AppendDetails("授权码保存失败")
	}
	if err := db.R.Set(ctx, authCodeCacheKey(crypto.HashSHA512(code)), payload, cfg.C.OAuthCodeTTL).Err(); err != nil {
		return "", errs.CreateAndLogInternalError(err, "Failed to store oauth authorization code").AppendDetails("Redis 错误")
	}
	return code, nil
}

// takeAuthorizationCode 取出授权码后立即删除，即使后续校验失败也不可复用。
func takeAuthorizationCode(ctx context.Context, code string) (*authorizationCode, *errs.Error) {
	value, err := getDelScript.Run(ctx, db.R, []string{authCodeCacheKey(crypto.HashSHA512(code))}).Text()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, errs.CreateAndLogInternalError(err, "Failed to take oauth authorization code").AppendDetails("Redis 错误")
	}

	var record authorizationCode
	if err := json.Unmarshal([]byte(value), &record); err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to unmarshal oauth authorization code").AppendDetails("授权码解析失败")
	}
	if !time.Now().Before(record.ExpiresAt) {
		return nil, nil
	}
	return &record, nil
}

// ---------------------------------------------------------------------------
// 设备码
// ---------------------------------------------------------------------------

type deviceCodeRecord struct {
	UserCode        string                      `json:"user_code"`
	AppID           int64                       `json:"app_id"`
	Permissions     []string                    `json:"permissions"`
	Status          model.OAuthDeviceCodeStatus `json:"status"`
	IntervalSeconds int32                       `json:"interval_seconds"`
	LastPolledAt    int64                       `json:"last_polled_at"` // Unix 毫秒，0 表示尚未轮询
	AuthID          int64                       `json:"auth_id"`        // 用户同意后写入
	UserID          int64                       `json:"user_id"`        // 同意/拒绝的用户
	ExpiresAt       int64                       `json:"expires_at"`     // Unix 毫秒
}

var storeDeviceCodeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 or redis.call('EXISTS', KEYS[2]) == 1 then
    return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
return 1
`)

func tryStoreDeviceCode(
	ctx context.Context,
	deviceCode string,
	record *deviceCodeRecord,
	ttl time.Duration,
) (bool, *errs.Error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return false, errs.CreateAndLogInternalError(err, "Failed to marshal oauth device code").AppendDetails("设备码保存失败")
	}

	deviceHash := crypto.HashSHA512(deviceCode)
	result, err := storeDeviceCodeScript.Run(ctx, db.R, []string{
		deviceUserCodeCacheKey(record.UserCode),
		deviceCodeCacheKey(deviceHash),
	}, deviceHash, payload, ttlSeconds(ttl)).Int()
	if err != nil {
		return false, errs.CreateAndLogInternalError(err, "Failed to store oauth device code").AppendDetails("Redis 错误")
	}
	return result == 1, nil
}

func getDeviceCodeByUserCode(ctx context.Context, userCode string) (*deviceCodeRecord, string, *errs.Error) {
	deviceHash, e := db.R.Get(ctx, deviceUserCodeCacheKey(userCode)).Result()
	if e != nil {
		if errors.Is(e, redis.Nil) {
			return nil, "", nil
		}
		return nil, "", errs.CreateAndLogInternalError(e, "Failed to get oauth device code by user code").AppendDetails("Redis 错误")
	}
	record, err := getDeviceCodeByHash(ctx, deviceHash)
	if err != nil {
		return nil, "", err
	}
	return record, deviceHash, nil
}

func getDeviceCodeByHash(ctx context.Context, deviceHash string) (*deviceCodeRecord, *errs.Error) {
	payload, err := db.R.Get(ctx, deviceCodeCacheKey(deviceHash)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, errs.CreateAndLogInternalError(err, "Failed to get oauth device code").AppendDetails("Redis 错误")
	}

	var record deviceCodeRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		_ = db.R.Del(ctx, deviceCodeCacheKey(deviceHash)).Err()
		return nil, errs.CreateAndLogInternalError(err, "Failed to unmarshal oauth device code").AppendDetails("设备码解析失败")
	}
	return &record, nil
}

// 只允许从 pending 迁移；返回 1 成功、0 不存在或已处理、-1 已过期。
var decideDeviceCodeScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
    return 0
end
local data = cjson.decode(raw)
local now = tonumber(ARGV[4])
if data.expires_at and now >= tonumber(data.expires_at) then
    redis.call('DEL', KEYS[1])
    return -1
end
if data.status ~= 'pending' then
    return 0
end
data.status = ARGV[1]
data.auth_id = tonumber(ARGV[2])
data.user_id = tonumber(ARGV[3])
redis.call('SET', KEYS[1], cjson.encode(data), 'KEEPTTL')
return 1
`)

func decideDeviceCode(
	ctx context.Context,
	deviceHash string,
	status model.OAuthDeviceCodeStatus,
	authID, userID int64,
) (int64, *errs.Error) {
	result, err := decideDeviceCodeScript.Run(ctx, db.R, []string{deviceCodeCacheKey(deviceHash)},
		string(status), authID, userID, time.Now().UnixMilli(),
	).Int64()
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to decide oauth device code").AppendDetails("Redis 错误")
	}
	return result, nil
}

type devicePollEnvelope struct {
	Status string            `json:"status"`
	Record *deviceCodeRecord `json:"record"`
}

// approved 时删除设备码并返回记录，保证令牌只能换一次。
var pollDeviceCodeScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw then
    return cjson.encode({status='missing'})
end
local data = cjson.decode(raw)
local now = tonumber(ARGV[1])
local expectedApp = tonumber(ARGV[2])
if tonumber(data.app_id) ~= expectedApp then
    return cjson.encode({status='invalid'})
end
if data.expires_at and now >= tonumber(data.expires_at) then
    redis.call('DEL', KEYS[1])
    return cjson.encode({status='expired'})
end
if data.status == 'approved' then
    redis.call('DEL', KEYS[1])
    return cjson.encode({status='approved', record=cjson.decode(raw)})
end
if data.status == 'denied' then
    return cjson.encode({status='denied'})
end
local interval = (tonumber(data.interval_seconds) or 4) * 1000
local tooFast = false
if data.last_polled_at and tonumber(data.last_polled_at) > 0 and now - tonumber(data.last_polled_at) < interval then
    tooFast = true
end
data.last_polled_at = now
redis.call('SET', KEYS[1], cjson.encode(data), 'KEEPTTL')
if tooFast then
    return cjson.encode({status='too_fast'})
end
return cjson.encode({status='pending'})
`)

func pollDeviceCode(
	ctx context.Context,
	deviceCode string,
	expectedAppID int64,
) (*devicePollEnvelope, *errs.Error) {
	value, err := pollDeviceCodeScript.Run(ctx, db.R, []string{
		deviceCodeCacheKey(crypto.HashSHA512(deviceCode)),
	}, time.Now().UnixMilli(), expectedAppID).Text()
	if err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to poll oauth device code").AppendDetails("Redis 错误")
	}

	var envelope devicePollEnvelope
	if err := json.Unmarshal([]byte(value), &envelope); err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to unmarshal oauth device poll result").AppendDetails("设备码解析失败")
	}
	return &envelope, nil
}

// ---------------------------------------------------------------------------
// 授权确认请求
// ---------------------------------------------------------------------------

func SaveConsentRequest(ctx context.Context, req *ConsentRequest) *errs.Error {
	if req == nil {
		return errs.BadRequestError().AppendDetails("未提供授权请求")
	}
	if err := db.SetRedis(ctx, consentRequestCacheKey(req.ID), req, cfg.C.OAuthConsentRequestTTL); err != nil {
		return err
	}
	return nil
}

// TakeConsentRequest 取出并删除确认请求；同一 request_id 只能确认一次。
func TakeConsentRequest(ctx context.Context, id string) (*ConsentRequest, *errs.Error) {
	raw, err := db.R.GetDel(ctx, consentRequestCacheKey(id)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, errs.CreateAndLogInternalError(err, "Failed to take oauth consent request").AppendDetails("Redis 错误")
	}

	var req ConsentRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to unmarshal oauth consent request").AppendDetails("授权请求解析失败")
	}
	return &req, nil
}
