package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "net/http/pprof"

	"github.com/stretchr/testify/require"
	accessContract "go.dedis.ch/dela/contracts/access"
	"go.dedis.ch/dela/core/txn"
	"go.dedis.ch/dela/core/txn/signed"
	"go.dedis.ch/dela/crypto/bls"
	"go.dedis.ch/dela/crypto/loader"
	"go.dedis.ch/dela/dkg"
	"go.dedis.ch/dela/dkg/pedersen"
	"go.dedis.ch/dela/dkg/pedersen/types"
	"go.dedis.ch/dela/serde/json"
	"golang.org/x/xerrors"

	"go.dedis.ch/dela/mino"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/xof/keccak"
)

// QUESTIONS
// HOW DO WE UPDATE THE DELAY FROM KEY GENERATION?

func init() {
	rand.Seed(0)
}

func Test_F3B_Mine(t *testing.T) {

	// SETUP VARIABLES
	// batch size => the number of scenarios we run
	// numDKGs => smc size
	// numNodes => number of DELA nodes
	batchSizes := []int{1}
	// numDKGs := []int{3, 10, 20, 30, 50, 70, 100}
	numDKGs := []int{3}
	withGrpc := false
	numNodes := 3

	// Run testscenario for number of batches, number of SMC Nodes
	for _, batchSize := range batchSizes {
		for _, numDKG := range numDKGs {
			t.Run(fmt.Sprintf("batch size %d num dkg %d", batchSize, numDKG),
				f3bScenario_Auction(batchSize, numDKG, numNodes, withGrpc))
		}
	}
}

// Tests the F3B Auction scenario
func f3bScenario_Auction(batchSize, numDKG, numNodes int, withGrpc bool) func(t *testing.T) {
	return func(t *testing.T) {

		require.Greater(t, numDKG, 0)
		require.Greater(t, numNodes, 0)
		require.GreaterOrEqual(t, numDKG, numNodes)

		to := time.Second * 10 // transaction inclusion timeout

		// set up the
		// NOTE: mino is used to send messages between nodes
		minosBuilder := getMinoch
		if withGrpc {
			minosBuilder = getMinogRPCs
		}

		minos := minosBuilder(t, numDKG)
		dkgs := make([]dkg.DKG, numDKG)
		addrs := make([]mino.Address, numDKG)

		// initializing the addresses
		for i, mino := range minos {
			addrs[i] = mino.GetAddress()
		}

		// Create public keys for each node
		pubkeys := make([]kyber.Point, len(minos))

		for i, mino := range minos {
			dkg, pubkey := pedersen.NewPedersen(mino)
			dkgs[i] = dkg
			pubkeys[i] = pubkey
		}

		// used to setup dkg with collective authority, encrypt/decrypt functionality
		actors := make([]dkg.Actor, numDKG)
		for i := 0; i < numDKG; i++ {
			actor, err := dkgs[i].Listen()
			require.NoError(t, err)
			actors[i] = actor
		}

		// Creates new collective authority
		fakeAuthority := NewAuthority(addrs, pubkeys)
		start := time.Now()
		_, err := actors[0].Setup(fakeAuthority, numDKG)
		require.NoError(t, err)

		setupTime := time.Since(start)
		fmt.Println("setup done in ", setupTime)
		t.Logf("setup done in %s", setupTime)

		// setting up the blockchain

		dir, err := os.MkdirTemp("", "dela-integration-test")
		require.NoError(t, err)

		t.Logf("using temps dir %s", dir)

		defer os.RemoveAll(dir)

		nodes := make([]dela, numNodes)

		for i := range nodes {
			nodes[i] = newDelaNode(t, filepath.Join(dir, fmt.Sprintf("node%d", i)), 0)
		}

		nodes[0].Setup(nodes[1:]...)

		l := loader.NewFileLoader(filepath.Join(dir, "private.key"))

		// creating a new client/signer
		signerdata, err := l.LoadOrCreate(newKeyGenerator())
		require.NoError(t, err)

		signer, err := bls.NewSignerFromBytes(signerdata)
		require.NoError(t, err)

		pubKey := signer.GetPublicKey()
		cred := accessContract.NewCreds(aKey[:])

		for _, node := range nodes {
			node.GetAccessService().Grant(node.(cosiDelaNode).GetAccessStore(), cred, pubKey)
		}

		manager := signed.NewManager(signer, &txClient{})

		pubKeyBuf, err := signer.GetPublicKey().MarshalBinary()
		require.NoError(t, err)

		// sending the value contract grant transaction to the blockchain
		args := []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Value")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		// waiting for the confirmation of the transaction
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// // Giving access to auction contract
		// args = []txn.Arg{
		// 	{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
		// 	{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
		// 	{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Auction")},
		// 	{Key: "access:grant_command", Value: []byte("all")},
		// 	{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
		// 	{Key: "access:command", Value: []byte("GRANT")},
		// }
		// err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		// require.NoError(t, err)

		// Giving access to auctionF3B contract
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// AUCTION INIT COMMAND
		// Bid length = 3
		bidLength := []byte("3")
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
			{Key: "value:initBidLength", Value: bidLength},
			{Key: "value:command", Value: []byte("INIT")},
		}
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)
		// Check Bid Length set correctly
		initBidKey := []byte("auction:bid_length")
		proof, err := nodes[0].GetOrdering().GetProof(initBidKey)
		require.NoError(t, err)
		require.Equal(t, bidLength, proof.GetValue())

		// // AUCTION INIT COMMAND: ENCRYPTED VERSION
		// keys := make([][29]byte, batchSize)
		// for i := range keys {
		// 	_, err = rand.Read(keys[i][:])
		// 	require.NoError(t, err)
		// }
		// key := getAESKey(keys[0])
		// bidLength := []byte("3")
		// args = []txn.Arg{
		// 	{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
		// 	{Key: "value:initBidLength", Value: bidLength},
		// 	{Key: "value:command", Value: []byte("INIT")},
		// }
		// etx := getEncryptedTX(t, manager, key, args...)
		// dtx := getDecryptedTX(etx, key)
		// err = addAndWaitDecrypted(t, to, manager, nodes[0].(cosiDelaNode), dtx)
		// // Check Bid Length set correctly
		// initBidKey := []byte("auction:bid_length")
		// proof, err := nodes[0].GetOrdering().GetProof(initBidKey)
		// require.NoError(t, err)
		// require.Equal(t, bidLength, proof.GetValue())

		// creating GBar. we need a generator in order to follow the encryption and
		// decryption protocol of https://arxiv.org/pdf/2205.08529.pdf / we take an
		// agreed data among the participants and embed it as a point. the result is
		// the generator that we are seeking
		var suite = suites.MustFind("Ed25519")
		agreedData := make([]byte, 32)
		_, err = rand.Read(agreedData)
		require.NoError(t, err)
		gBar := suite.Point().Embed(agreedData, keccak.New(agreedData))

		// creating the symmetric keys in batch. we process the transactions in
		// batch to increase the throughput for more information refer to
		// https://arxiv.org/pdf/2205.08529.pdf / page 6 / step 1 (write
		// transaction)

		// the write transaction arguments
		argSlice := make([][]txn.Arg, batchSize)

		var ciphertexts []types.Ciphertext

		// generate random messages to be encrypted
		// NOTE: These are the symmetric keys to be encrypted
		fmt.Println("Generate random messages to be encrypted")
		keys := make([][29]byte, batchSize)
		for i := range keys {
			_, err = rand.Read(keys[i][:])
			require.NoError(t, err)
		}

		// PRINT KEYS
		fmt.Println("PRINTING KEYS")
		for i := range keys {
			fmt.Println("Key: ", keys[i][:])
		}
		// Encrypt message with keys
		fmt.Println("SYMMETRIC ENCRYPTION OF MESSAGE USING KEYS")
		pt := []byte("Plain Text!")
		key := getAESKey(keys[0])
		ct := symmetricEncrypt(pt, key)
		dct := symmetricDecrypt(ct, key)
		require.Equal(t, dct, pt)

		// // TODO: Encrypt bid tx with symmetric key
		// pt = []byte("Plain Text")
		// key := []byte("passphrasewhichneedstobe32bytes!")
		// fmt.Println("pt: ", pt)
		// ct = symmetricEncrypt(pt, key)
		// fmt.Println("Encrypted Message: ", ct)
		// dct = symmetricDecrypt(ct, key)
		// fmt.Println("dct: ", dct)
		// require.Equal(t, dct, pt)

		// // TODO: Check TX Encrypt and Decrypt
		// thisTX := getTX(t, manager, args...)
		// // thisTXSerialize, err := thisTX.Serialize(thisTX)
		// cTX := symmetricEncrypt(thisTXSerialize, key)
		// pTX := symmetricDecrypt(cTX, key)
		// thisTXUnserialized, err := signed.NewTransactionFactory().TransactionOf(ctx, pTX)
		// // thisTXUnserialized, err := signed.NewTransactionFactory().TransactionOf(ctx, thisTXSerialize)
		// fmt.Println("**********************************************************")
		// fmt.Println("***** This TX Serialized")
		// fmt.Println(thisTX)
		// fmt.Println("***** This TX UnSerialized")
		// fmt.Println(thisTXUnserialized)
		// fmt.Println("***** Error?")
		// fmt.Println(err)
		// fmt.Println("**********************************************************")

		// ctx = json.NewContext()
		// // thisTXByte2, err := thisTX.GetIdentity().MarshalText()
		// thisTXByte, err = thisTX.Serialize(ctx)
		// thisTXByteToTX, err = signed.NewTransactionFactory().Deserialize(ctx, thisTXByte)
		// ct = symmetricEncrypt(thisTXByte, key)
		// dct = symmetricDecrypt(ct, key)
		// require.Equal(t, dct, thisTXByte)

		// fmt.Println("**********************************************************")
		// fmt.Println("***** This TX Serialized")
		// fmt.Println(thisTX)
		// fmt.Println("***** This TX Deserialized")
		// fmt.Println(thisTXByteToTX)
		// fmt.Println("**********************************************************")

		// TODO: How to deserialize tx?

		start = time.Now()

		// Create a Write instance
		for i := 0; i < batchSize; i++ {
			t.Log("INSIDE Write Instance")
			t.Log("I: ", i)
			aesKey := getAESKey(keys[i])

			// Encrypting the symmetric key with PKsmc
			ciphertext, remainder, err := actors[0].VerifiableEncrypt(keys[i][:], gBar)
			require.NoError(t, err)
			require.Len(t, remainder, 0)

			ciphertexts = append(ciphertexts, ciphertext)

			// converting the kyber.Point or kyber.Scalar to bytes
			Cbytes, err := ciphertext.C.MarshalBinary()
			require.NoError(t, err)
			Ubytes, err := ciphertext.K.MarshalBinary()
			require.NoError(t, err)
			Ubarbytes, err := ciphertext.UBar.MarshalBinary()
			require.NoError(t, err)
			Ebytes, err := ciphertext.E.MarshalBinary()
			require.NoError(t, err)
			Fbytes, err := ciphertext.F.MarshalBinary()
			require.NoError(t, err)

			// put all the data together
			// NOTE: Ck is the encrypted symmetric key
			Ck := append(Cbytes[:], Ubytes[:]...)
			Ck = append(Ck, Ubarbytes[:]...)
			Ck = append(Ck, Ebytes[:]...)
			Ck = append(Ck, Fbytes[:]...)

			// creating the transaction to write Ck, make sure written correctly
			key := []byte("key1")
			argSlice[i] = getWriteArgs(key, Ck)
			// Make sure value tx did not yield error
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), argSlice[i]...)
			require.NoError(t, err)
			// Make sure value tx correct
			proof, err := nodes[0].GetOrdering().GetProof([]byte("key1"))
			require.NoError(t, err)
			require.Equal(t, Ck, proof.GetValue())

			// TODO: Write encrypted bid TX
			// Create encrypted Bid TX
			bid := []byte("2")
			args = getBidArgs(bid)
			etx := getEncryptedTX(t, manager, aesKey, args...)
			key = []byte("key1")
			writeArgs := getWriteArgs(key, etx)
			// Make sure value tx did not yield error
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), writeArgs...)
			require.NoError(t, err)
			// Make sure value tx correct
			proof, err = nodes[0].GetOrdering().GetProof([]byte("key1"))
			require.NoError(t, err)
			require.Equal(t, etx, proof.GetValue())
		}

		submitTime := time.Since(start)
		t.Logf("submit batch: %s", submitTime)

		start = time.Now()

		// decrypting the symmetric key in batch
		fmt.Println("Decrypting symmetric key")
		decrypted, _, _, err := actors[0].VerifiableDecrypt(ciphertexts)
		require.NoError(t, err)

		decryptTime := time.Since(start)
		t.Logf("decrypt batch: %s", decryptTime)

		// make sure that the decryption was correct
		fmt.Println("Check decryption")
		for i := 0; i < batchSize; i++ {
			require.Equal(t, keys[i][:], decrypted[i])
		}

		// TODO: Get the bid transactions, decrypt them, and submit to bid auction

		// SELECTWINNER COMMAND
		// Create and hash bid/nonce
		// args = []txn.Arg{
		// 	{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
		// 	{Key: "value:command", Value: []byte("SELECTWINNER")},
		// }
		// err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		// require.NoError(t, err)

		fmt.Println("Setup,\tSubmit,\tDecrypt")
		fmt.Printf("%d,\t%d,\t%d\n", setupTime.Milliseconds(), submitTime.Milliseconds(), decryptTime.Milliseconds())
	}
}

// -----------------------------------------------------------------------------
// Utility functions

// func addAndWait(t *testing.T, to time.Duration, manager txn.Manager, node cosiDelaNode, args ...txn.Arg) error {
func getTX(t *testing.T, manager txn.Manager, args ...txn.Arg) txn.Transaction {
	// manager.Sync()

	tx, err := manager.Make(args...)
	require.NoError(t, err)

	return tx
}

func getEncryptedTX(t *testing.T, manager txn.Manager, key []byte, args ...txn.Arg) []byte {
	tx := getTX(t, manager, args...)
	ctx := json.NewContext()
	thisTXByte, _ := tx.Serialize(ctx)
	ct := symmetricEncrypt(thisTXByte, key)

	return ct
}

func getDecryptedTX(ct []byte, key []byte) txn.Transaction {
	// Decrypt tx
	dtx := symmetricDecrypt(ct, key)
	// Convert []byte to txn.Transaction
	ctx := json.NewContext()
	tx, _ := signed.NewTransactionFactory().TransactionOf(ctx, dtx)

	return tx
}

func getBidArgs(bid []byte) []txn.Arg {
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
		{Key: "value:bid", Value: bid},
		{Key: "value:command", Value: []byte("BID")},
	}

	return args
}

func getWriteArgs(key []byte, val []byte) []txn.Arg {
	args := []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Value")},
		{Key: "value:key", Value: []byte(key)},
		{Key: "value:value", Value: []byte(val)},
		{Key: "value:command", Value: []byte("WRITE")},
	}

	return args
}

func addAndWaitDecrypted(t *testing.T, to time.Duration, manager txn.Manager, node cosiDelaNode, tx txn.Transaction) error {
	manager.Sync()

	// tx, err := manager.Make(args...)
	// require.NoError(t, err)

	err := node.GetPool().Add(tx)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()

	events := node.GetOrdering().Watch(ctx)

	for event := range events {
		for _, result := range event.Transactions {
			tx := result.GetTransaction()

			if bytes.Equal(tx.GetID(), tx.GetID()) {
				accepted, err := event.Transactions[0].GetStatus()
				require.Empty(t, err)

				require.True(t, accepted)
				return nil
			}
		}
	}

	return xerrors.Errorf("transaction not found")
}
