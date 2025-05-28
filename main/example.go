package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

// Placeholder for your custom error package
var (
	errorInvalidKey = "invalid key length"

	errorspkg = struct {
		NewError func(code int, level string, err error, context interface{}, message string) error
		// Define error types/levels
		InternalServerError int
		WARNING             string
	}{
		NewError: func(code int, level string, err error, context interface{}, message string) error {
			return fmt.Errorf("[%d:%s] %s", code, level, message)
		},
		InternalServerError: 500,
		WARNING:             "WARNING",
	}
)

// PKCS5UnPadding removes padding from decrypted text
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func GetAESDecrypted(encrypted, key string, action string) (string, error) {
	if len(key) < 32 {
		return "", errorspkg.NewError(errorspkg.InternalServerError,
			errorspkg.WARNING, nil, nil, errorInvalidKey)
	}

	iv := key[:16]

	var ciphertext []byte
	var err error
	if action == "s2s" {
		ciphertext, err = base64.RawStdEncoding.DecodeString(encrypted)
	} else {
		ciphertext, err = base64.StdEncoding.DecodeString(encrypted)
	}

	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return string(ciphertext), nil
}

