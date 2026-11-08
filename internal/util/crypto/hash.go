package crypto

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ---------------------------------------------------------------------------
// Sha512
// ---------------------------------------------------------------------------

// HashSHA512 计算 SHA-512 并编码为小写十六进制串，用于会话令牌等随机串的存储摘要。
// 注意：这里是对高熵随机串做单向摘要，无需加盐；密码必须使用 Argon2id。
func HashSHA512(token string) string {
	sum := sha512.Sum512([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Argon2ID
// ---------------------------------------------------------------------------

const (
	argonTime    = 3         // 迭代次数
	argonMemory  = 64 * 1024 // 内存开销，单位 KiB（64 MiB）
	argonThreads = 4         // 并行度
	argonKeyLen  = 32        // 输出摘要长度（字节）
	argonSaltLen = 32        // 随机盐长度（字节）
)

// HashArgon2ID 用 Argon2id 和随机盐哈希密码，返回 PHC 格式字符串（含参数、盐与摘要）。
func HashArgon2ID(str string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(str), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyArgon2ID 按 PHC 字符串中的参数重新计算 Argon2id 摘要并做常量时间比较。
// 注意：哈希参数从存储的字符串读取，旧参数的哈希仍可校验；字符串格式非法时返回 error。
func VerifyArgon2ID(str, encodedHash string) (bool, error) {
	params, salt, hash, err := decodeArgon2IDHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(str), salt, params.time, params.memory, params.threads, uint32(len(hash)))

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

// burnPasswordHash 是 BurnPasswordVerifyCost 使用的固定 PHC 哈希，参数与 HashArgon2ID 一致。
const burnPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$A/VMpUldqzUMDLbcsbpY+h5JSyK7nMhY/laPBS2n2hs$mQcGzal+0cYbaOXUo9MO9jzhXFFG3+r2XtkX5Bh05Ww"

// BurnPasswordVerifyCost 对固定串执行一次 Argon2id 校验。
// 用于用户不存在等分支，拉平与「密码错误」分支的响应耗时，防止通过时延枚举账号。
func BurnPasswordVerifyCost() {
	_, _ = VerifyArgon2ID("dummy-password-for-timing-equalization", burnPasswordHash)
}

// params 是 Argon2id PHC 字符串中记录的哈希参数。
type params struct {
	memory  uint32
	time    uint32
	threads uint8
}

// decodeArgon2IDHash 解析 PHC 格式的 Argon2id 哈希，返回参数、盐与原始摘要。
func decodeArgon2IDHash(encodedHash string) (*params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("incompatible argon2 version")
	}

	var p params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode hash: %w", err)
	}

	return &p, salt, hash, nil
}
