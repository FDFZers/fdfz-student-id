package crypto

import (
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/model"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GenerateToken(uuid uuid.UUID, claims *model.TokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &model.RegisteredTokenClaims{
		*claims,
		jwt.RegisteredClaims{
			Issuer:    "fdfz-student-id",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.C.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.String(),
		},
	})
	return token.SignedString(cfg.C.JWTSecret)
}

func ParseToken(tokenString string) (*model.RegisteredTokenClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&model.RegisteredTokenClaims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return cfg.C.JWTSecret, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
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
