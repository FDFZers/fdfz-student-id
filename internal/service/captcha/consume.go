package captcha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/altcha-org/altcha-lib-go/v2"
)

// UsedAltchaCacheKey 返回记录已消费 Altcha challenge 的 Redis key。
// 注意：参数名为 email，但当前调用方传入的是 challenge 的 SHA-256 指纹，key 前缀与语义不符。
func UsedAltchaCacheKey(email string) string {
	return fmt.Sprintf("student_id:altcha:used:email:%s", strings.ToLower(strings.TrimSpace(email)))
}

// TryConsumeAltchaChallenge 用 Redis SetNX 标记 challenge 已消费，防止同一 payload 重放。
// 标记 TTL 与 challenge 有效期对齐：按 ALTCHA_TIMEOUT 的 2 倍封顶、最少 1 秒。
func TryConsumeAltchaChallenge(ctx context.Context, payload altcha.Payload) *errs.Error {
	params := payload.Challenge.Parameters

	// 计算消费标记的 TTL
	ttl := cfg.C.AltchaTimeout
	if params.ExpiresAt > 0 {
		ttl = time.Until(time.Unix(params.ExpiresAt, 0))
		if maxTTL := 2 * cfg.C.AltchaTimeout; ttl > maxTTL {
			ttl = maxTTL
		}
		if ttl < time.Second {
			ttl = time.Second
		}
	}
	// 存疑：上面计算出的 ttl 未被使用，SetNX 固定使用 ALTCHA_TIMEOUT，疑似应传入 ttl。

	// 以签名、nonce、salt 与过期时间生成 challenge 指纹
	sum := sha256.Sum256([]byte(
		payload.Challenge.Signature + "|" +
			params.Nonce + "|" +
			params.Salt + "|" +
			strconv.FormatInt(params.ExpiresAt, 10),
	))

	// SetNX 成功表示首次消费，失败表示该 challenge 已被使用
	ok, err := db.R.SetNX(ctx, UsedAltchaCacheKey(hex.EncodeToString(sum[:])), true, cfg.C.AltchaTimeout).Result()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to consume altcha challenge").AppendDetails("Redis 错误", "Altcha Challenge 消费失败")
	} else if !ok {
		return errs.AltchaError().AppendDetails("请重新进行人机验证")
	}
	return nil
}
