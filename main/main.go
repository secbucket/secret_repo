package main

import (
	"fmt"
	"crypto/aes"
)

func main() {
	// Example usage of GetAESDecrypted

	// Example 32-byte key (replace with your own secure key)
	key := "12345678901234567890123456789012"

	// Example base64-encoded ciphertext (this is just a placeholder)
	encrypted := "QmFzZTY0RW5jb2RlZENpcGhlcnRleHQ=" // Not real encrypted data
	action := "default" // or "s2s" if using raw encoding

	decrypted, err := GetAESDecrypted(encrypted, key, action)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted text:", decrypted)
}
