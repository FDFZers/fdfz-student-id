// Package crypto 提供验证码与 TOTP 生成、密码哈希、令牌摘要以及 JWT 签发/校验等密码学工具。
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
	// CodeCharset 是邮箱/QQ 验证码字符集：大写字母加数字，便于用户手动输入。
	CodeCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// TokenCharset 是会话令牌字符集：大小写字母加数字，用于不可猜测的长随机串。
	TokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// GenerateCode 使用 crypto/rand 从 charset 中均匀随机取 length 个字符。
// 注意：调用方需保证 charset 非空；length 为 0 时返回空串。
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

// GenerateTOTP 为指定用户生成 TOTP 密钥与 otpauth URL（SHA512、6 位、30 秒周期）。
// 返回的 secret 写入数据库，URL 交给前端生成二维码供用户扫码绑定。
func GenerateTOTP(userID uint64) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FDFZ Student ID",
		AccountName: strconv.FormatUint(userID, 10),
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA512,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// VerifyTOTP 校验 TOTP 验证码，参数需与 GenerateTOTP 一致。
// 注意：Skew=1，即允许前后各一个 30 秒时间窗口的时钟偏差。
func VerifyTOTP(secret string, code string) (bool, error) {
	return totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	})
}
