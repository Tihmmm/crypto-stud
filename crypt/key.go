package crypt

import (
	"crypto/rand"
)

func RandKey(lengthBytes int) ([]byte, error) {
	buf := make([]byte, lengthBytes)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
