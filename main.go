package main

import (
	"bytes"
	"errors"
	"log"
	"siw2/crypt"
)

func main() {
	message := "hello world"

	// Демонстрация шифрования и расшифрования сообщения `message` с помощью AES-GCM-256
	demoAesEncryption(message)
	log.Println("\n\n")
	// Демонстрация подписи сообщения `message` и ее верификация с помощью
	demoRsaSignature(message)
}

func demoAesEncryption(plaintext string) {

	plaintextBytes := []byte("hello world")
	log.Printf("encrypting message: %v. in unicode: %s", plaintextBytes, plaintext)

	aes, err := crypt.NewAes(nil)
	if err != nil {
		panic(err)
	}
	ciphertext, err := aes.Encrypt(plaintextBytes)
	if err != nil {
		panic(errors.New("error encrypting: " + err.Error()))
	}
	log.Printf("ciphertext: %v", ciphertext)

	decryptedBytes, err := aes.Decrypt(ciphertext)
	if err != nil {
		panic(errors.New("error decrypting: " + err.Error()))
	}
	log.Printf("decryptedText: %v", decryptedBytes)

	if !bytes.Equal(plaintextBytes, decryptedBytes) {
		panic(errors.New("decrypted text does not match plaintext"))
	} else {
		log.Printf("successfully encrypted and decrypted message")
	}
}

func demoRsaSignature(message string) {
	messageBytes := []byte(message)
	log.Printf("signing message: %v. in unicode: %s", messageBytes, message)

	signer, err := crypt.NewRsaSigner(nil)
	if err != nil {
		panic(err)
	}

	signature, err := signer.SignPKCS1v15(messageBytes)
	if err != nil {
		panic(err)
	}
	log.Printf("signature: %v", signature)

	verifier, err := crypt.NewRsaVerifier(signer.PublicKey)
	if err != nil {
		panic(err)
	}

	log.Printf("sig length: %d", len(signature))

	if _, err := verifier.VerifyPKCS1v15(messageBytes, messageBytes); err != nil {
		log.Printf("invalid signature (as expected): %v", err)
	}

	valid, err := verifier.VerifyPKCS1v15(messageBytes, signature)
	if err != nil {
		log.Printf("error verifying signature: %v", err)
		return
	}
	if valid {
		log.Printf("valid signature (as expected)")
	}
}
