package crypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type RsaSigner struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func NewRsaSigner(privateKey *rsa.PrivateKey) (*RsaSigner, error) {
	if privateKey == nil {
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}

	return &RsaSigner{
		privateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func (s *RsaSigner) SignPKCS1v15(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(nil, s.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return signature, nil
}

type RsaVerifier struct {
	SignerPublicKey *rsa.PublicKey
}

func NewRsaVerifier(publicKey *rsa.PublicKey) (*RsaVerifier, error) {
	if publicKey == nil {
		return nil, errors.New("public key is nil")
	}

	return &RsaVerifier{
		SignerPublicKey: publicKey,
	}, nil
}

func (v *RsaVerifier) VerifyPKCS1v15(message []byte, signature []byte) (bool, error) {
	hashed := sha256.Sum256(message)
	if err := rsa.VerifyPKCS1v15(v.SignerPublicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return false, err
	}

	return true, nil
}
