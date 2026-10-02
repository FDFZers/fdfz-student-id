package captcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/altcha-org/altcha-lib-go/v2"
)

var AltchaError = errs.CreateError(http.StatusForbidden, "altcha")

func CreateChallenge() (altcha.Challenge, error) {
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:           "PBKDF2/SHA-256",
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: cfg.C.AltchaHMACSecret,
		Cost:                5000,
		KeyLength:           32,
	})
}

func VerifyChallenge(payload altcha.Payload) (res altcha.VerifySolutionResult, err error) {
	defer func() {
		// 我也不知道为什么 ALTCHA 能 panic
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

func VerifyPayloadStr(payloadStr string) *errs.Error {
	if cfg.C.BypassCaptcha {
		slog.Debug("Bypassed captcha")
		return nil
	}

	jsonBytes, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return errs.BadRequestError().AppendDetails("Altcha 载荷无效")
	}
	var payload altcha.Payload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return errs.BadRequestError().AppendDetails("Altcha 载荷无效")
	}

	result, err := VerifyChallenge(payload)
	if err != nil {
		return AltchaError.AppendDetails("Altcha 内部错误")
	}
	if !result.Verified {
		return AltchaError.AppendDetails("Altcha Challenge 无效")
	}
	if result.Expired {
		return AltchaError.AppendDetails("Altcha Challenge 过期")
	}
	return nil
}
