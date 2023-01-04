package integration

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	accessContract "go.dedis.ch/dela/contracts/access"
	auctionContract "go.dedis.ch/dela/contracts/auction"
	"go.dedis.ch/dela/core/txn"
	"go.dedis.ch/dela/core/txn/signed"
	"go.dedis.ch/dela/crypto/bls"
	"go.dedis.ch/dela/crypto/loader"
)

func init() {
	rand.Seed(0)
}

// Tests Throughput with 3 Dela Nodes
func TestAuction_Throughput(t *testing.T) {
	// Number of bids and trials for testing
	numBids := 10
	numTrials := 35
	var results []float64

	for i := 0; i < numTrials; i++ {
		dir, err := os.MkdirTemp(os.TempDir(), "dela-integration-test")
		require.NoError(t, err)

		timeout := time.Second * 10 // transaction inclusion timeout

		t.Logf("using temps dir %s", dir)

		defer os.RemoveAll(dir)

		// Create 3 nodes
		nodes := []dela{
			newDelaNode(t, filepath.Join(dir, "node1"), 0),
			newDelaNode(t, filepath.Join(dir, "node2"), 0),
			newDelaNode(t, filepath.Join(dir, "node3"), 0),
		}

		nodes[0].Setup(nodes[1:]...)

		l := loader.NewFileLoader(filepath.Join(dir, "private.key"))

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

		// Giving access to value contract
		args := []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Value")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// Giving access to auction contract
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Auction")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// AUCTION INIT COMMAND
		// Bid length = 2, Reveal length = 2
		bidLength := []byte(strconv.Itoa(numBids))
		revealLength := []byte(strconv.Itoa(numBids))
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
			{Key: "value:initBidLength", Value: bidLength},
			{Key: "value:initRevealLength", Value: revealLength},
			{Key: "value:command", Value: []byte("INIT")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// Measuring throughput
		start := time.Now()
		for j := 0; j < numBids; j++ {
			// BID COMMAND
			// Create and hash bid/nonce
			bidBid := []byte(strconv.Itoa(j))
			bidNonce := []byte("Nonce")
			bid, err := hashReveal(bidBid, bidNonce)
			require.NoError(t, err)
			bidDeposit := []byte(strconv.Itoa(j))
			args = []txn.Arg{
				{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
				{Key: "value:bid", Value: bid},
				{Key: "value:bidDeposit", Value: bidDeposit},
				{Key: "value:command", Value: []byte("BID")},
			}
			err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
			require.NoError(t, err)
		}
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
	t.Log("***** Testing Throughput")
	t.Log("Number of bids: ", numBids)
	t.Log("Number of trials: ", numTrials)
	t.Logf("average bid throughput: %f", average)
}

func TestAuction_Latency(t *testing.T) {
	// Number of bids and trials for testing
	numBids := 10
	numTrials := 35
	var results []float64
	to := time.Second * 10 // transaction inclusion timeout

	for i := 0; i < numTrials; i++ {
		dir, err := os.MkdirTemp(os.TempDir(), "dela-integration-test")
		require.NoError(t, err)

		timeout := time.Second * 10 // transaction inclusion timeout

		t.Logf("using temps dir %s", dir)

		defer os.RemoveAll(dir)

		// Create 3 nodes
		nodes := []dela{
			newDelaNode(t, filepath.Join(dir, "node1"), 0),
			newDelaNode(t, filepath.Join(dir, "node2"), 0),
			newDelaNode(t, filepath.Join(dir, "node3"), 0),
		}

		nodes[0].Setup(nodes[1:]...)

		l := loader.NewFileLoader(filepath.Join(dir, "private.key"))

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

		// Measuring latencu
		start := time.Now()

		// Giving access to value contract
		args := []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Value")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// Giving access to auction contract
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte("go.dedis.ch/dela.Access")},
			{Key: "access:grant_id", Value: []byte(hex.EncodeToString(valueAccessKey[:]))},
			{Key: "access:grant_contract", Value: []byte("go.dedis.ch/dela.Auction")},
			{Key: "access:grant_command", Value: []byte("all")},
			{Key: "access:identity", Value: []byte(base64.StdEncoding.EncodeToString(pubKeyBuf))},
			{Key: "access:command", Value: []byte("GRANT")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// AUCTION INIT COMMAND
		bidLength := []byte(strconv.Itoa(numBids))
		revealLength := []byte(strconv.Itoa(numBids))
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
			{Key: "value:initBidLength", Value: bidLength},
			{Key: "value:initRevealLength", Value: revealLength},
			{Key: "value:command", Value: []byte("INIT")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

		// BID Commands
		// Create and hash bid/nonce
		for j := 0; j < numBids; j++ {
			bidBid := []byte(strconv.Itoa(j))
			bidNonce := []byte("Nonce")
			bid, err := hashReveal(bidBid, bidNonce)
			require.NoError(t, err)
			bidDeposit := []byte(strconv.Itoa(j))
			args = []txn.Arg{
				{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
				{Key: "value:bid", Value: bid},
				{Key: "value:bidDeposit", Value: bidDeposit},
				{Key: "value:command", Value: []byte("BID")},
			}
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
			require.NoError(t, err)
		}

		// REVEAL Commands
		for j := 0; j < numBids; j++ {
			// Create and hash bid/nonce
			revealBid := []byte(strconv.Itoa(0))
			revealNonce := []byte("Nonce")
			args = []txn.Arg{
				{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
				{Key: "value:revealBid", Value: revealBid},
				{Key: "value:revealNonce", Value: revealNonce},
				{Key: "value:command", Value: []byte("REVEAL")},
			}
			err = addAndWait(t, to, manager, nodes[0].(cosiDelaNode), args...)
			require.NoError(t, err)
		}

		// SELECTWINNER COMMAND
		args = []txn.Arg{
			{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
			{Key: "value:command", Value: []byte("SELECTWINNER")},
		}
		err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
		require.NoError(t, err)

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
	t.Logf("average duration of transactions: %f", average)
}
