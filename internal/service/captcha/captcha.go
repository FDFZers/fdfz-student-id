package captcha

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fmt"
	"log/slog"
	"time"

	"github.com/altcha-org/altcha-lib-go/v2"
)

// CreateChallenge 生成带 HMAC 签名与过期时间的 Altcha v2 challenge（PBKDF2/SHA-256，cost 16384）。
// 过期时间取当前时间加 ALTCHA_TIMEOUT。
func CreateChallenge() (altcha.Challenge, error) {
	expiresAt := time.Now().Add(cfg.C.AltchaTimeout)
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:           "PBKDF2/SHA-256",
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: cfg.C.AltchaHMACSecret,
		Cost:                16384,
		KeyLength:           32,
		ExpiresAt:           &expiresAt,
	})
}

// VerifyChallenge 校验 Altcha payload 的签名、解与有效期，返回校验结果。
// 注意：altcha 库在部分输入下可能 panic，这里 recover 后统一转成 error。
func VerifyChallenge(payload altcha.Payload) (res altcha.VerifySolutionResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = fmt.Errorf("altcha error: %v", x)
			}
		}
	}()
	return altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:           payload.Challenge,
		Solution:            payload.Solution,
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: cfg.C.AltchaHMACSecret,
	})
}

// VerifyPayloadStr 解析 Base64 编码的 Altcha payload，校验后消费 challenge 防止重放。
// 注意：BYPASS_CAPTCHA 仅在非生产环境可开启，开启后直接放行。
func VerifyPayloadStr(ctx context.Context, payloadStr string) *errs.Error {
	// 调试开关：跳过人机验证
	if cfg.C.BypassCaptcha {
		slog.Debug("Bypassed captcha")
		return nil
	}

	// 解码 Base64 载荷并解析 JSON
	jsonBytes, e := base64.StdEncoding.DecodeString(payloadStr)
	if e != nil {
		return errs.BadRequestError().AppendDetails("Altcha 载荷格式错误")
	}
	var payload altcha.Payload
	if e := json.Unmarshal(jsonBytes, &payload); e != nil {
		return errs.BadRequestError().AppendDetails("Altcha 载荷格式错误")
	}

	// 校验签名、解与有效期
	result, e := VerifyChallenge(payload)
	if e != nil {
		return errs.AltchaError().AppendDetails("Altcha 内部错误")
	}
	if result.Expired {
		return errs.AltchaError().AppendDetails("Altcha Challenge 已过期")
	}
	if !result.Verified {
		return errs.AltchaError().AppendDetails("Altcha Challenge 校验失败")
	}

	// 用 Redis SetNX 保证同一 challenge 只消费一次
	if err := TryConsumeAltchaChallenge(ctx, payload); err != nil {
		return err
	}
	return nil
}
