package crypto

import (
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GenerateTOTP(userID uint64) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FDFZ Student ID",
		AccountName: strconv.FormatUint(userID, 10),
		Algorithm:   otp.AlgorithmSHA512,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func VerifyTOTP(secret string, code string) (bool, error) {
	c, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return false, err
	}
	return c == code, nil
}
