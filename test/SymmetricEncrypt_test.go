package integration

import (
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	_ "net/http/pprof"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/dela/core/txn"
	"go.dedis.ch/dela/core/txn/signed"
	"go.dedis.ch/dela/crypto/bls"
	"go.dedis.ch/dela/crypto/loader"
	"go.dedis.ch/dela/serde/json"
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
	ct := symmetricEncrypt(pt, key)
	dct := symmetricDecrypt(ct, key)
	require.Equal(t, dct, pt)

	// TRYING TO ENCRYPT/DECRYPT TX
	// TODO: Create bid tx
	bid := []byte("2")
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
		{Key: "value:bid", Value: bid},
		{Key: "value:command", Value: []byte("BID")},
	}

	dir, _ := os.MkdirTemp("", "dela-integration-test")
	l := loader.NewFileLoader(filepath.Join(dir, "private.key"))
	signerdata, _ := l.LoadOrCreate(newKeyGenerator())
	signer, _ := bls.NewSignerFromBytes(signerdata)
	manager := signed.NewManager(signer, &txClient{})

	thisTX := getTX(t, manager, args...)
	ctx := json.NewContext()
	thisTXByte, _ := thisTX.Serialize(ctx)
	ct = symmetricEncrypt(thisTXByte, key)
	dct = symmetricDecrypt(ct, key)
	require.Equal(t, dct, thisTXByte)

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
