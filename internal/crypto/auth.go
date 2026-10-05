package crypto

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ---------------------------------------------------------------------------
// 验证码
// ---------------------------------------------------------------------------

const (
	CodeCharset  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	TokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func GenerateCode(length int, charset string) (string, error) {
	result := make([]byte, length)
	maxIndex := big.NewInt(int64(len(charset)))

	for i := range length {
		idx, err := rand.Int(rand.Reader, maxIndex)
		if err != nil {
			return "", err
		}
		result[i] = charset[idx.Int64()]
	}
	return string(result), nil
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

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
