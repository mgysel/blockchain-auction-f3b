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
	"go.dedis.ch/dela/crypto"
	"go.dedis.ch/dela/crypto/bls"
	"go.dedis.ch/dela/crypto/loader"
	"go.dedis.ch/dela/serde/json"
)

func Test_Encrypt2(t *testing.T) {
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
	ct := symmetricEncrypt2(t, pt, key)
	dct := symmetricDecrypt2(ct, key)
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
	// manager := signed.NewManager(signer, &txClient{})

	// Make TX
	thisTX := makeTx2(t, 0, signer, args...)
	t.Log("thisTX: ", thisTX)
	ctx := json.NewContext()
	thisTXByte, _ := thisTX.Serialize(ctx)
	t.Log("thisTXByte: ", thisTXByte)

	// Encrypt and Decrypt
	ct = symmetricEncrypt2(t, thisTXByte, key)
	t.Log("CT: ", ct)
	dct = symmetricDecrypt2(ct, key)
	t.Log("DCT: ", string(dct))
	require.Equal(t, dct, thisTXByte)

	// // thisTX := getTX(t, manager, args...)
	// thisTX, _ := signed.NewTransaction(0, signer.GetPublicKey(), signed.WithArg("A", []byte{1}))
	// thisTX.Sign(signer)
	// t.Log("thisTX: ", thisTX)
	// ctx := json.NewContext()
	// thisTXByte, _ := thisTX.Serialize(ctx)
	// t.Log("thisTX: ", thisTXByte)

	// _, err := signer.GetPublicKey().MarshalBinary()
	// options := []signed.TransactionOption{}
	// for i := 0; i < len(args)-1; i += 2 {
	// 	options = append(options, signed.WithArg(args[i], []byte(args[i+1])))
	// }

	// tx, err := signed.NewTransaction(0, signer.GetPublicKey(), options...)
	// require.NoError(t, err)

	// _, err := signer.GetPublicKey().MarshalBinary()
	// tx, err := signed.NewTransaction(2, signer.GetPublicKey(), signed.WithArg("A", []byte{1, 2, 3}))
	// tx.Sign(signer)
	// t.Log("TX: ", tx)
	// require.NoError(t, err)

	// ctx := json.NewContext()
	// // ctx := serde.NewContext(fake.ContextEngine{})
	// data, err := tx.Serialize(ctx)
	// t.Log("DATA: ", data)
	// require.NoError(t, err)

	// NOTE: WHEN SERIALIZING -> GOES TO NO BYTES

	// t.Log("ThisTXByte: ", thisTXByte)
	// ct := symmetricEncrypt2(t, thisTXByte, key)
	// dct := symmetricDecrypt2(ct, key)
	// t.Log("DCT: ", string(dct))
	// require.Equal(t, dct, thisTXByte)

}

// func makeTx2(t *testing.T, signer crypto.Signer, args ...string) txn.Transaction {
// 	_, err := signer.GetPublicKey().MarshalBinary()
// 	options := []signed.TransactionOption{}
// 	for i := 0; i < len(args)-1; i += 2 {
// 		options = append(options, signed.WithArg(args[i], []byte(args[i+1])))
// 	}

// 	tx, err := signed.NewTransaction(0, signer.GetPublicKey(), options...)
// 	tx.Sign(signer)
// 	require.NoError(t, err)

// 	return tx
// }

func makeTx2(t *testing.T, nonce uint64, signer crypto.Signer, args ...txn.Arg) txn.Transaction {
	_, err := signer.GetPublicKey().MarshalBinary()
	options := []signed.TransactionOption{}
	for i := 0; i < len(args); i += 1 {
		options = append(options, signed.WithArg(args[i].Key, args[i].Value))
	}

	tx, err := signed.NewTransaction(nonce, signer.GetPublicKey(), options...)
	tx.Sign(signer)
	require.NoError(t, err)

	return tx
}

// AES symmetric encryption
// Source: https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
func symmetricEncrypt2(t *testing.T, pt []byte, key []byte) []byte {
	t.Log("***** Inside symmetricEncrypt2")
	t.Log("pt: ", pt)
	t.Log("key: ", key)

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
func symmetricDecrypt2(ct []byte, key []byte) []byte {
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

// func getTX2(t *testing.T, manager txn.Manager, args ...txn.Arg) txn.Transaction {
// 	// manager.Sync()

// 	tx, err := manager.Make(args...)
// 	t.Log("*** Inside GetTX2")
// 	t.Log("TX: ")
// 	require.NoError(t, err)

// 	return tx
// }
