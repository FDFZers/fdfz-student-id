package crypto

import (
	"crypto/subtle"
	"strings"
)

// code_challenge 使用 SHA-512 十六进制摘要，长度固定 128。
const (
	CodeChallengeLength = 128
	CodeVerifierMinLen  = 48
	CodeVerifierMaxLen  = 128
)

func GenerateCodeChallenge(verifier string) string {
	return HashSHA512(verifier)
}

// ValidCodeChallenge 判断 challenge 是否合法；空串表示不使用该机制。
func ValidCodeChallenge(challenge string) bool {
	if challenge == "" {
		return true
	}
	if len(challenge) != CodeChallengeLength {
		return false
	}
	return isHexString(challenge)
}

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

// validCodeVerifierCharset 判断字符串是否只含 RFC 7636 允许的 unreserved 字符。
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
