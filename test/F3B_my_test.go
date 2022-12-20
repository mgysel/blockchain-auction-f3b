package integration

import (
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

		// Test Bid
		bid := []byte("1")
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
			{Key: "value:bid", Value: bid},
			{Key: "value:command", Value: []byte("BID")},
		}
		err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)
		// Check Highest Bid set correctly
		highestBidKey := []byte("auction:highest_bid")
		proof, err = nodes[0].GetOrdering().GetProof(highestBidKey)
		require.NoError(t, err)
		require.Equal(t, string(bid), string(proof.GetValue()))

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

		// TODO: Create bid tx
		bid = []byte("2")
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.AuctionF3B")},
			{Key: "value:bid", Value: bid},
			{Key: "value:command", Value: []byte("BID")},
		}

		// TODO: Encrypt bid tx with symmetric key

		start = time.Now()

		// Create a Write instance
		for i := 0; i < batchSize; i++ {
			t.Log("INSIDE Write Instance")
			t.Log("I: ", i)

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

			// creating the transaction to write Ck
			argSlice[i] = []txn.Arg{
				{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Value")},
				{Key: "value:key", Value: []byte("key1")},
				{Key: "value:value", Value: Ck},
				{Key: "value:command", Value: []byte("WRITE")},
			}

			// TODO: create the transaction to write the encrypted transaction

			// we read the recorded data on the blockchain and make sure that
			// the data was submitted correctly
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), argSlice[i]...)
			require.NoError(t, err)

			// Make sure value tx correct
			proof, err := nodes[0].GetOrdering().GetProof([]byte("key1"))
			require.NoError(t, err)
			require.Equal(t, Ck, proof.GetValue())
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
