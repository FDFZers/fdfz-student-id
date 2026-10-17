package crypto

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	jwtPrivateKey *rsa.PrivateKey
	jwtPublicKey  *rsa.PublicKey
	JWKS          string
)

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
	_ = key.Set(jwk.KeyIDKey, cfg.C.JWTKeyID)
	_ = key.Set(jwk.AlgorithmKey, jwa.RS512)
	_ = key.Set(jwk.KeyUsageKey, "sig")

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

func GenerateJWT(id uuid.UUID, claims *model.TokenClaims) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, &model.RegisteredTokenClaims{
		TokenClaims: *claims,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "fdfz-student-id",
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.C.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id.String(),
		},
	})
	token.Header[jwk.KeyIDKey] = cfg.C.JWTKeyID
	return token.SignedString(jwtPrivateKey)
}

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
