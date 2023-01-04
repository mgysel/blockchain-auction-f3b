package integration

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
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

func Test_F3BAuction_Latency(t *testing.T) {

	// SETUP VARIABLES
	// batch size => the number of scenarios we run
	// numDKGs => smc size
	// numNodes => number of DELA nodes
	numBids := []int{10}
	numTrials := 1
	numDKGs := []int{8}
	withGrpc := false
	numNodes := 3

	// Run testscenario for number of batches, number of SMC Nodes
	for _, numBid := range numBids {
		for _, numDKG := range numDKGs {
			t.Run(fmt.Sprintf("num bids %d num dkg %d", numBid, numDKG),
				f3b_Auction_Latency(numBid, numTrials, numDKG, numNodes, withGrpc))
		}
	}
}

// Tests the F3B Auction scenario
func f3b_Auction_Latency(numBids, numTrials, numDKG, numNodes int, withGrpc bool) func(t *testing.T) {
	return func(t *testing.T) {
		var results []float64

		for i := 0; i < numTrials; i++ {

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
			_, err := actors[0].Setup(fakeAuthority, numDKG)
			require.NoError(t, err)

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
			// signer2, err := bls.NewSignerFromBytes(signerdata)
			require.NoError(t, err)

			pubKey := signer.GetPublicKey()
			cred := accessContract.NewCreds(aKey[:])

			for _, node := range nodes {
				node.GetAccessService().Grant(node.(cosiDelaNode).GetAccessStore(), cred, pubKey)
			}

			manager := signed.NewManager(signer, &txClient{})
			// manager := signed.NewManager(signer, &txClient{nonce: 5})

			pubKeyBuf, err := signer.GetPublicKey().MarshalBinary()
			require.NoError(t, err)

			start := time.Now()

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
			fmt.Println("BATCH SIZE: ", fmt.Sprint(numBids))
			bidLength := []byte(fmt.Sprint(numBids))
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
			argSlice := make([][]txn.Arg, numBids)

			var ciphertexts []types.Ciphertext

			// generate random messages to be encrypted
			// NOTE: These are the symmetric keys to be encrypted
			fmt.Println("Generate random messages to be encrypted")
			keys := make([][29]byte, numBids)
			for i := range keys {
				_, err = rand.Read(keys[i][:])
				require.NoError(t, err)
			}

			// Create a Write instance
			for i := 0; i < numBids; i++ {
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

				// Put all the data together
				// NOTE: Ck is the encrypted symmetric key
				Ck := append(Cbytes[:], Ubytes[:]...)
				Ck = append(Ck, Ubarbytes[:]...)
				Ck = append(Ck, Ebytes[:]...)
				Ck = append(Ck, Fbytes[:]...)

				// WRITE 1: Write Ck
				// creating the transaction to write Ck, make sure written correctly
				thisCkKey := []byte(fmt.Sprintf("Ck:%s", fmt.Sprint(i)))
				argSlice[i] = getWriteArgs(thisCkKey, Ck)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), argSlice[i]...)
				require.NoError(t, err)
				// Make sure value tx correct
				proof, err := nodes[0].GetOrdering().GetProof(thisCkKey)
				require.NoError(t, err)
				require.Equal(t, Ck, proof.GetValue())

				// WRITE 2: Write encrypted bid TX
				// Create encrypted Bid TX
				bid := []byte(fmt.Sprint(i + 1))
				args = getBidArgs(bid)
				nonce := uint64(3 + (numBids * 2) + (i * 3) + 2)
				etx := getEncryptedTX(t, nonce, signer, aesKey, args...)
				thisEtxKey := []byte(fmt.Sprintf("etx:%s", fmt.Sprint(i)))
				writeArgs := getWriteArgs(thisEtxKey, etx)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), writeArgs...)
				require.NoError(t, err)
				// Make sure value tx correct
				proof, err = nodes[0].GetOrdering().GetProof(thisEtxKey)
				require.NoError(t, err)
				require.Equal(t, etx, proof.GetValue())
			}

			// Read/Decrypt/Submit TX
			for i := 0; i < numBids; i++ {
				aesKey := getAESKey(keys[i])

				// Read Ck
				// creating the transaction to read Ck
				thisCkKey := []byte(fmt.Sprintf("Ck:%s", fmt.Sprint(i)))
				readArgs := getReadArgs(thisCkKey)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), readArgs...)
				require.NoError(t, err)
				// Get Ck value
				proof, err := nodes[0].GetOrdering().GetProof(thisCkKey)

				// Decrypt Ck value
				fmt.Println("Decrypting symmetric key")
				decrypted, _, _, err := actors[0].VerifiableDecrypt([]types.Ciphertext{ciphertexts[i]})
				require.NoError(t, err)

				// make sure that the decryption was correct
				fmt.Println("Check decryption")
				require.Equal(t, keys[i][:], decrypted[0])

				// Read Encrypted Bid TX
				thisEtxKey := []byte(fmt.Sprintf("etx:%s", fmt.Sprint(i)))
				readArgs = getReadArgs(thisEtxKey)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), readArgs...)
				require.NoError(t, err)
				// Get Encrypted TX value
				proof, err = nodes[0].GetOrdering().GetProof(thisEtxKey)
				etx := proof.GetValue()

				// Decrypt TX
				dtx := getDecryptedTX(etx, aesKey)

				// Submit TX
				err = addAndWaitDecrypted(t, to, manager, nodes[0].(cosiDelaNode), dtx)
				require.NoError(t, err)
			}

			// Check Winner
			args = getSelectWinnerArgs()
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
			require.NoError(t, err)
			require.Equal(t, strconv.Itoa(numBids), string(proof.GetValue()))

			end := time.Since(start).Seconds()
			t.Log("This trial: ", end)
			results = append(results, float64(end))
		}

		// Determine results
		sum := float64(0)
		for i := 0; i < numTrials; i++ {
			sum += (results[i])
		}

		average := sum / float64(numTrials)
		t.Log("***** Testing Duration")
		t.Log("Number of bids: ", numBids)
		t.Log("Number of trials: ", numTrials)
		t.Logf("average auction duration: %f", average)
	}
}

func Test_F3BAuction_Throughput(t *testing.T) {

	// SETUP VARIABLES
	// batch size => the number of scenarios we run
	// numDKGs => smc size
	// numNodes => number of DELA nodes
	numBids := []int{100}
	numTrials := 1
	numDKGs := []int{8}
	withGrpc := false
	numNodes := 3

	// Run testscenario for number of batches, number of SMC Nodes
	for _, numBid := range numBids {
		for _, numDKG := range numDKGs {
			t.Run(fmt.Sprintf("num bids %d num dkg %d", numBid, numDKG),
				f3b_Auction_Throughput(numBid, numTrials, numDKG, numNodes, withGrpc))
		}
	}
}

// Tests the F3B Auction scenario
func f3b_Auction_Throughput(numBids, numTrials, numDKG, numNodes int, withGrpc bool) func(t *testing.T) {
	return func(t *testing.T) {
		var results []float64

		for i := 0; i < numTrials; i++ {

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
			_, err := actors[0].Setup(fakeAuthority, numDKG)
			require.NoError(t, err)

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
			// signer2, err := bls.NewSignerFromBytes(signerdata)
			require.NoError(t, err)

			pubKey := signer.GetPublicKey()
			cred := accessContract.NewCreds(aKey[:])

			for _, node := range nodes {
				node.GetAccessService().Grant(node.(cosiDelaNode).GetAccessStore(), cred, pubKey)
			}

			manager := signed.NewManager(signer, &txClient{})
			// manager := signed.NewManager(signer, &txClient{nonce: 5})

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
			fmt.Println("BATCH SIZE: ", fmt.Sprint(numBids))
			bidLength := []byte(fmt.Sprint(numBids))
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
			argSlice := make([][]txn.Arg, numBids)

			var ciphertexts []types.Ciphertext

			// generate random messages to be encrypted
			// NOTE: These are the symmetric keys to be encrypted
			fmt.Println("Generate random messages to be encrypted")
			keys := make([][29]byte, numBids)
			for i := range keys {
				_, err = rand.Read(keys[i][:])
				require.NoError(t, err)
			}

			start := time.Now()

			// Create a Write instance
			for i := 0; i < numBids; i++ {
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

				// Put all the data together
				// NOTE: Ck is the encrypted symmetric key
				Ck := append(Cbytes[:], Ubytes[:]...)
				Ck = append(Ck, Ubarbytes[:]...)
				Ck = append(Ck, Ebytes[:]...)
				Ck = append(Ck, Fbytes[:]...)

				// WRITE 1: Write Ck
				// creating the transaction to write Ck, make sure written correctly
				thisCkKey := []byte(fmt.Sprintf("Ck:%s", fmt.Sprint(i)))
				argSlice[i] = getWriteArgs(thisCkKey, Ck)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), argSlice[i]...)
				require.NoError(t, err)
				// Make sure value tx correct
				proof, err := nodes[0].GetOrdering().GetProof(thisCkKey)
				require.NoError(t, err)
				require.Equal(t, Ck, proof.GetValue())

				// WRITE 2: Write encrypted bid TX
				// Create encrypted Bid TX
				bid := []byte(fmt.Sprint(i + 1))
				args = getBidArgs(bid)
				nonce := uint64(3 + (numBids * 2) + (i * 3) + 2)
				etx := getEncryptedTX(t, nonce, signer, aesKey, args...)
				thisEtxKey := []byte(fmt.Sprintf("etx:%s", fmt.Sprint(i)))
				writeArgs := getWriteArgs(thisEtxKey, etx)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), writeArgs...)
				require.NoError(t, err)
				// Make sure value tx correct
				proof, err = nodes[0].GetOrdering().GetProof(thisEtxKey)
				require.NoError(t, err)
				require.Equal(t, etx, proof.GetValue())
			}

			// Read/Decrypt/Submit TX
			for i := 0; i < numBids; i++ {
				aesKey := getAESKey(keys[i])

				// Read Ck
				// creating the transaction to read Ck
				thisCkKey := []byte(fmt.Sprintf("Ck:%s", fmt.Sprint(i)))
				readArgs := getReadArgs(thisCkKey)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), readArgs...)
				require.NoError(t, err)
				// Get Ck value
				proof, err := nodes[0].GetOrdering().GetProof(thisCkKey)

				// Decrypt Ck value
				fmt.Println("Decrypting symmetric key")
				decrypted, _, _, err := actors[0].VerifiableDecrypt([]types.Ciphertext{ciphertexts[i]})
				require.NoError(t, err)

				// make sure that the decryption was correct
				fmt.Println("Check decryption")
				require.Equal(t, keys[i][:], decrypted[0])

				// Read Encrypted Bid TX
				thisEtxKey := []byte(fmt.Sprintf("etx:%s", fmt.Sprint(i)))
				readArgs = getReadArgs(thisEtxKey)
				// Make sure value tx did not yield error
				err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), readArgs...)
				require.NoError(t, err)
				// Get Encrypted TX value
				proof, err = nodes[0].GetOrdering().GetProof(thisEtxKey)
				etx := proof.GetValue()

				// Decrypt TX
				dtx := getDecryptedTX(etx, aesKey)

				// Submit TX
				err = addAndWaitDecrypted(t, to, manager, nodes[0].(cosiDelaNode), dtx)
				require.NoError(t, err)
			}

			end := time.Since(start).Seconds()

			// Check Winner
			args = getSelectWinnerArgs()
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
			require.NoError(t, err)
			require.Equal(t, strconv.Itoa(numBids), string(proof.GetValue()))

			t.Log("This trial: ", end)
			results = append(results, float64(end))
		}

		// Determine results
		sum := float64(0)
		for i := 0; i < numTrials; i++ {
			sum += (results[i])
		}

		average := sum / float64(numTrials)
		t.Log("***** Testing Duration")
		t.Log("Number of bids: ", numBids)
		t.Log("Number of trials: ", numTrials)
		t.Logf("average duration of transactions: %f", average)
	}
}
