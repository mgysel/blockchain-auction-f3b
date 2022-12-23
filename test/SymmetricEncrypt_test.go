package integration

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"testing"

	_ "net/http/pprof"

	"github.com/stretchr/testify/require"
)

func Test_Encrypt(t *testing.T) {
	// Generate keys
	fmt.Println("Generate random messages to be encrypted")
	batchSize := 2
	keys := make([][29]byte, batchSize)
	fmt.Println("Keys: ", keys)
	for i := range keys {
		key, err := rand.Read(keys[i][:])
		fmt.Println("Key: ", key)
		require.NoError(t, err)
	}

	// Must append key to make 32 Bytes as opposed to 29 Bytes
	key := getAESKey(keys[0])
	pt := []byte("Plain Text")
	// key := []byte("passphrasewhichneedstobe32bytes!")
	fmt.Println("String key: ", key)
	fmt.Println("pt: ", pt)

	ct := symmetricEncrypt(pt, key)
	fmt.Println("Encrypted Message: ", ct)

	dct := symmetricDecrypt(ct, key)

	require.Equal(t, dct, pt)
}

// AES symmetric encryption
// Source: https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
func symmetricEncrypt(pt []byte, key []byte) []byte {
	// New aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	// nonce required to encrypt pt
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(cryptoRand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// Encrypt pt
	ct := gcm.Seal(nonce, nonce, pt, nil)
	fmt.Println(ct)

	return ct
}

// AES Symmetric Decryption
// Source: https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
func symmetricDecrypt(ct []byte, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ct) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ct[:nonceSize], ct[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(pt))

	return pt
}

func getAESKey(key [29]byte) []byte {
	AESKey := append(key[:], 0, 0, 0)
	return AESKey
}
