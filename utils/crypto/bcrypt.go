package crypto

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

func VerifyBcrypt(password, encodedHash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
