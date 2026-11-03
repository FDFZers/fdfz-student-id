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

func UsedAltchaCacheKey(email string) string {
	return fmt.Sprintf("student_id:altcha:used:email:%s", strings.ToLower(strings.TrimSpace(email)))
}
func TryConsumeAltchaChallenge(ctx context.Context, payload altcha.Payload) *errs.Error {
	params := payload.Challenge.Parameters

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

	sum := sha256.Sum256([]byte(
		payload.Challenge.Signature + "|" +
			params.Nonce + "|" +
			params.Salt + "|" +
			strconv.FormatInt(params.ExpiresAt, 10),
	))

	ok, err := db.R.SetNX(ctx, UsedAltchaCacheKey(hex.EncodeToString(sum[:])), true, cfg.C.AltchaTimeout).Result()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to consume altcha challenge").AppendDetails("Redis 错误", "Altcha Challenge 消费失败")
	} else if !ok {
		return errs.AltchaError().AppendDetails("请重新进行人机验证")
	}
	return nil
}
