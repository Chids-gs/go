package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"fmt"
		"encoding/base64"

)

// AES aes
const (
	AesIvLen      = 16
	AesKeyLen     = 32
	AesKeyCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
func base64EncodeStripped(s string) string {
    encoded := base64.StdEncoding.EncodeToString([]byte(s))
    return strings.TrimRight(encoded, "=")
}

func base64DecodeStripped(s string) (string, error) {
    if i := len(s) % 4; i != 0 {
        s += strings.Repeat("=", 4-i)
    }
    decoded, err := base64.StdEncoding.DecodeString(s)
    return string(decoded), err
}
func main(){
	data:="CodeAnywhere"
	aesKey := NewAesKey()
	// encrypt data using AES
	
	body, err := AesEncrypt([]byte(data), aesKey)
	encoded := base64EncodeStripped(string(body))
	
	decoded, err := base64DecodeStripped(encoded)
	

	body1,err :=AesDecrypt([]byte(decoded),aesKey)
	
	fmt.Println(string(body1),err)
	
	
}

func AesEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = paddingPKCS7(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, AesIvLen)

	blockModel := cipher.NewCBCEncrypter(block, iv)
	blockModel.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// AesDecrypt decrypts data using the specified key
func AesDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, AesIvLen)
	plaintext := make([]byte, len(ciphertext))

	blockModel := cipher.NewCBCDecrypter(block, iv)
	blockModel.CryptBlocks(plaintext, ciphertext)
	plaintext = unpaddingPKCS7(plaintext, block.BlockSize())
	return plaintext, nil
}

func NewAesKey() []byte {
	key := "be3be04389eb7c67f8baa3084ec0c8c5"
	return []byte(key)
}

func paddingPKCS7(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func unpaddingPKCS7(plaintext []byte, blockSize int) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}