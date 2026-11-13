package crypto

import (
	"crypto/rsa"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"time"

	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	jwtPrivateKey *rsa.PrivateKey // 签发访问令牌/提权令牌用的 RSA 私钥
	jwtPublicKey  *rsa.PublicKey  // 校验令牌签名用的 RSA 公钥
	// JWKS 是由公钥生成的 JWK Set JSON，通过 /auth/jwks 暴露给其他服务离线校验签名。
	JWKS string
)

// LoadJWTKeys 从 SHARED_DIR/certs/jwt 读取 RSA 私钥/公钥，并生成带 kid 与 RS512 算法的 JWKS。
// 注意：必须在签发/校验令牌前调用一次；任一文件缺失或解析失败都会导致服务启动失败。
func LoadJWTKeys() error {
	dir := path.Join(cfg.C.SharedDir, "certs", "jwt")
	privBytes, err := os.ReadFile(path.Join(dir, "private.pem"))
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	priv, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	pubBytes, err := os.ReadFile(path.Join(dir, "public.pem"))
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pub, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	key, err := jwk.Import(pub)
	if err != nil {
		return fmt.Errorf("create JWK from public key: %w", err)
	}
	if err := key.Set(jwk.KeyIDKey, cfg.C.JWTKeyID); err != nil {
		return fmt.Errorf("set JWK key id: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS512()); err != nil {
		return fmt.Errorf("set JWK algorithm: %w", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return fmt.Errorf("set JWK key usage: %w", err)
	}

	set := jwk.NewSet()
	_ = set.AddKey(key)

	jwtPrivateKey = priv
	jwtPublicKey = pub

	if bytes, err := json.Marshal(set); err != nil {
		return fmt.Errorf("marshal JWKS: %w", err)
	} else {
		JWKS = string(bytes)
	}

	return nil
}

// GenerateJWT 使用 RS512 签发 JWT，jti 取传入的 id，签发者固定为 fdfz-student-id。
// 注意：签发前会复制并排序权限/所属应用列表，保证相同授权得到稳定的令牌内容，不会修改入参。
func GenerateJWT(id uuid.UUID, claims *model.TokenClaims, ttl time.Duration) (string, error) {
	now := time.Now()

	claimsCopy := *claims
	claimsCopy.Permissions = slices.Clone(claims.Permissions)
	slices.Sort(claimsCopy.Permissions)
	claimsCopy.OwnedApps = slices.Clone(claims.OwnedApps)
	slices.Sort(claimsCopy.OwnedApps)

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, &model.RegisteredTokenClaims{
		TokenClaims: claimsCopy,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "fdfz-student-id",
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id.String(),
		},
	})
	token.Header[jwk.KeyIDKey] = cfg.C.JWTKeyID
	return token.SignedString(jwtPrivateKey)
}

// ParseJWT 校验签名算法（RS512）、签发者、过期时间并返回 claims，允许 5 秒时钟偏差。
// 注意：不校验 token_type，调用方需按用途自行判断（如提权令牌要求 TokenTypeStepup）。
func ParseJWT(tokenString string) (*model.RegisteredTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&model.RegisteredTokenClaims{},
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtPublicKey, nil
		},
		jwt.WithValidMethods([]string{"RS512"}),
		jwt.WithIssuer("fdfz-student-id"),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*model.RegisteredTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
