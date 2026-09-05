package crypto

import (
	"crypto/rand"
	"math/big"
)

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateCode(length int) (string, error) {
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
