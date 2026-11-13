package crypto

import (
	"crypto/subtle"
	"strings"
)

// code_challenge 使用 SHA-512 摘要的十六进制编码，长度固定 128。
// 本服务不强制使用 code_challenge；客户端提供时按下面的规则校验。
const (
	CodeChallengeLength = 128
	CodeVerifierMinLen  = 48
	CodeVerifierMaxLen  = 128
)

// GenerateCodeChallenge 返回 code_verifier 的 SHA-512 十六进制摘要。
func GenerateCodeChallenge(verifier string) string {
	return HashSHA512(verifier)
}

// ValidCodeChallenge 判断 challenge 是否合法：空串表示不使用该机制，否则必须是 128 位十六进制。
func ValidCodeChallenge(challenge string) bool {
	if challenge == "" {
		return true
	}
	if len(challenge) != CodeChallengeLength {
		return false
	}
	return isHexString(challenge)
}

// VerifyCodeChallenge 校验 code_verifier 的十六进制摘要是否与 code_challenge 一致。
// challenge 为空时直接通过；verifier 长度与字符集非法时判定失败。
func VerifyCodeChallenge(challenge, verifier string) bool {
	if challenge == "" {
		return true
	}
	if len(verifier) < CodeVerifierMinLen || len(verifier) > CodeVerifierMaxLen {
		return false
	}
	if !validCodeVerifierCharset(verifier) {
		return false
	}
	computed := GenerateCodeChallenge(verifier)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(strings.ToLower(challenge))) == 1
}

// isHexString 判断字符串是否全部由十六进制字符组成（大小写均可）。
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// validCodeVerifierCharset 判断字符串是否只包含 RFC 7636 允许的 unreserved 字符。
func validCodeVerifierCharset(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
