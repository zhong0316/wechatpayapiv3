package wechatpayv3

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

func ApiV3Aes256GCMDecrypt(associatedData, nonce, cipherText, apiV3Key []byte) (string, error) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	if len(apiV3Key) != 32 {
		return "", errors.New("无效的ApiV3Key，长度必须为32个字节")
	}
	block, err := aes.NewCipher(apiV3Key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 先对密文base64解码得到密文
	plaintext, err := base64.StdEncoding.DecodeString(string(cipherText))
	if err != nil {
		return "", err
	}

	// 在解密密文
	decrypted, err := aesgcm.Open(nil, nonce, plaintext, associatedData)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

//func ExampleNewGCMEncrypter() {
//	// The key argument should be the AES key, either 16 or 32 bytes
//	// to select AES-128 or AES-256.
//	key := []byte("AES256Key-32Characters1234567890")
//	plaintext := []byte("exampleplaintext")
//
//	block, err := aes.NewCipher(key)
//	if err != nil {
//		panic(err.Error())
//	}
//
//	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
//	nonce := make([]byte, 12)
//	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
//		panic(err.Error())
//	}
//
//	aesgcm, err := cipher.NewGCM(block)
//	if err != nil {
//		panic(err.Error())
//	}
//
//	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
//	fmt.Printf("%x\n", ciphertext)
//}
