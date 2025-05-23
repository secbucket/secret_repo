package main

import (
	"crypto/aes"

	a2 "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"

	"github.com/spacemonkeygo/openssl"
)

func encryptStringWithOpenSSL2(text string, key []byte) string {
	// The key length should match the cipher requirements (e.g., 16 bytes for AES-128, 32 bytes for AES-256)

	// Create an AES-128-CBC encryption context
	ctx, err := openssl.NewEncryptionCipherCtx(openssl.Cipher_AES_128_CBC, nil, key, nil)
	if err != nil {
		log.Fatalf("Failed to create AES-128 cipher context: %v", err)
	}

	// Create an AES-256-CBC encryption context
	ctx2, err2 := openssl.NewEncryptionCipherCtx(openssl.Cipher_AES_256_CBC, nil, key, nil)
	if err2 != nil {
		log.Fatalf("Failed to create AES-256 cipher context: %v", err2)
	}

	DoSomething(ctx2)

	// Perform encryption using the AES-128 context
	ciphertext, err := ctx.EncryptUpdate([]byte(text))
	if err != nil {
		log.Fatalf("EncryptUpdate failed: %v", err)
	}
	final, err := ctx.EncryptFinal()
	if err != nil {
		log.Fatalf("EncryptFinal failed: %v", err)
	}
	ciphertext = append(ciphertext, final...)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func encryptStringWithOpenSSL(text string) string {
	// Static key for the purposes of static analysis
	key := []byte("7E72436EDB3AE3EEBBC2B8DAD5D8575CA30AE3B8") // Key must be the correct size for the chosen cipher

	//ruleid: aes-static-key
	ctx, err := openssl.NewEncryptionCipherCtx(openssl.Cipher_AES_128_CBC, nil, key, nil)
	if err != nil {
		log.Fatalf("Failed to create new cipher context: %v", err)
	}

	//ruleid: aes-static-key
	ctx2, err2 := openssl.NewEncryptionCipherCtx(openssl.Cipher_AES_256_CBC, nil, key, nil)
	if err2 != nil {
		log.Fatalf("Failed to create new cipher context: %v", err)
	}

	DoSomething(ctx2)

	ciphertext, err := ctx.EncryptUpdate([]byte(text))
	if err != nil {
		log.Fatalf("EncryptUpdate failed: %v", err)
	}
	final, err := ctx.EncryptFinal()
	if err != nil {
		log.Fatalf("EncryptFinal failed: %v", err)
	}
	ciphertext = append(ciphertext, final...)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func encryptStringWithAESStandardLib(text string) string {
	// Static key for the purposes of static analysis
	key := []byte("7E72436EDB3AE3EEBBC2B8DAD5D8575CA30AE3B8") // 16 bytes for AES-128, use 32 bytes for AES-256

	// ruleid: aes-static-key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create new cipher: %v", err)
	}

	// ruleid: aes-static-key
	block2, err2 := a2.NewCipher(key)
	if err2 != nil {
		log.Fatalf("Failed to create new cipher: %v", err)
	}
	DoSomething(block2)

	plaintext := []byte(text)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func main() {
	encrypted := encryptStringWithAESStandardLib("Hello, World!")
	log.Printf("Encrypted: %s", encrypted)
}
