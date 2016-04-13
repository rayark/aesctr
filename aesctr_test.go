package aesctr_test

import (
	"encoding/hex"
	"fmt"
	"github.com/rayark/aesctr"
)

func Example() {
	msg := []byte("Hello World")
	key, _ := hex.DecodeString("0123456789ABCDEF0123456789ABCDEF")

	ciphertext, _ := aesctr.Encrypt(key, msg)
	decodedMsg, _ := aesctr.Decrypt(key, ciphertext)

	fmt.Println(string(decodedMsg))
	// Output: Hello World
}
