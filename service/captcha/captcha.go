package captcha

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fdfz-student-id/utils/errs"
	"fmt"
	"net/http"
	"os"

	"github.com/altcha-org/altcha-lib-go/v2"
)

var hmacSecret = os.Getenv("ALTCHA_HMAC_SECRET")

var AltchaExpiredError = errs.CreateError(http.StatusForbidden, "altcha_expired")
var AltchaInvalidError = errs.CreateError(http.StatusForbidden, "altcha_invalid")
var AltchaError = errs.CreateError(http.StatusInternalServerError, "altcha_error")

func CreateChallenge() (altcha.Challenge, error) {
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:           "PBKDF2/SHA-256",
		DeriveKey:           altcha.DeriveKeyPBKDF2(),
		HMACSignatureSecret: hmacSecret,
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
		HMACSignatureSecret: hmacSecret,
	})
}

func VerifyAndRespond(payloadStr string) *errs.Error {
	jsonBytes, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return errs.CreateInvalidFieldError("altcha_payload")
	}
	var payload altcha.Payload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return errs.CreateInvalidFieldError("altcha_payload")
	}

	result, err := VerifyChallenge(payload)
	if err != nil {
		return AltchaError
	}
	if !result.Verified {
		return AltchaInvalidError
	}
	if result.Expired {
		return AltchaExpiredError
	}
	return nil
}
