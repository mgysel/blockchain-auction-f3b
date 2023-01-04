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

	"github.com/stretchr/testify/require"
	accessContract "go.dedis.ch/dela/contracts/access"
	auctionContract "go.dedis.ch/dela/contracts/auction"
	"go.dedis.ch/dela/core/txn"
	"go.dedis.ch/dela/core/txn/signed"
	"go.dedis.ch/dela/crypto"
	"go.dedis.ch/dela/crypto/bls"
	"go.dedis.ch/dela/crypto/loader"
	"golang.org/x/xerrors"
)

func init() {
	rand.Seed(0)
}

// Start 3 nodes
// Use the auction contract
// Check the state
func TestIntegration_Auction(t *testing.T) {
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
	pubKeyByte, err := signer.GetPublicKey().MarshalText()
	pubKeyString := string(pubKeyByte)
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
	bidLength := []byte("1")
	revealLength := []byte("1")
	args = []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
		{Key: "value:initBidLength", Value: bidLength},
		{Key: "value:initRevealLength", Value: revealLength},
		{Key: "value:command", Value: []byte("INIT")},
	}
	err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
	require.NoError(t, err)

	// Check Bid Key set correctly
	initBidKey := []byte("auction:bid_length")
	proof, err := nodes[0].GetOrdering().GetProof(initBidKey)
	require.NoError(t, err)
	require.Equal(t, bidLength, proof.GetValue())

	// Check Reveal Key set correctly
	initRevealKey := []byte("auction:reveal_length")
	proof, err = nodes[0].GetOrdering().GetProof(initRevealKey)
	require.NoError(t, err)
	require.Equal(t, revealLength, proof.GetValue())

	// BID COMMAND
	// Create and hash bid/nonce
	bidBid := []byte("2")
	bidNonce := []byte("Nonce")
	bid, err := hashReveal(bidBid, bidNonce)
	require.NoError(t, err)
	bidDeposit := []byte("2")
	args = []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
		{Key: "value:bid", Value: bid},
		{Key: "value:bidDeposit", Value: bidDeposit},
		{Key: "value:command", Value: []byte("BID")},
	}
	err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
	require.NoError(t, err)

	// Check Bid PK set correctly
	key := []byte(fmt.Sprintf("bid:pk:0"))
	proof, err = nodes[0].GetOrdering().GetProof(key)
	require.NoError(t, err)
	require.Equal(t, pubKeyString, string(proof.GetValue()))

	// Check Bid set correctly
	key = []byte(fmt.Sprintf("bid:bid:0"))
	proof, err = nodes[0].GetOrdering().GetProof(key)
	require.NoError(t, err)
	require.Equal(t, bid, proof.GetValue())

	// REVEAL COMMAND
	// Create and hash bid/nonce
	revealBid := []byte("2")
	revealNonce := []byte("Nonce")
	args = []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
		{Key: "value:revealBid", Value: revealBid},
		{Key: "value:revealNonce", Value: revealNonce},
		{Key: "value:command", Value: []byte("REVEAL")},
	}
	err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
	require.NoError(t, err)

	// Check Reveal Bid set correctly
	key = []byte(fmt.Sprintf("reveal:bid:0"))
	proof, err = nodes[0].GetOrdering().GetProof(key)
	require.NoError(t, err)
	require.Equal(t, revealBid, proof.GetValue())

	// Check Reveal Nonce set correctly
	key = []byte(fmt.Sprintf("reveal:nonce:0"))
	proof, err = nodes[0].GetOrdering().GetProof(key)
	require.NoError(t, err)
	require.Equal(t, revealNonce, proof.GetValue())

	// SELECTWINNER COMMAND
	// Create and hash bid/nonce
	args = []txn.Arg{
		{Key: "go.dedis.ch/dela.ContractArg", Value: []byte(auctionContract.ContractName)},
		{Key: "value:command", Value: []byte("SELECTWINNER")},
	}
	err = addAndWait(t, timeout, manager, nodes[0].(cosiDelaNode), args...)
	require.NoError(t, err)

	// Check Highest Bidder set correctly
	key = []byte(fmt.Sprintf("auction:highest_bidder"))
	proof, err = nodes[0].GetOrdering().GetProof(key)
	require.NoError(t, err)
	require.Equal(t, pubKeyByte, proof.GetValue())

	// Check Highest Bid set correctly
	key = []byte(fmt.Sprintf("auction:highest_bid"))
	proof, err = nodes[0].GetOrdering().GetProof(key)
	require.NoError(t, err)
	require.Equal(t, revealBid, proof.GetValue())
}

// Helper functions

// Hashes a bid and nonce
func hashReveal(revealBid []byte, revealNonce []byte) ([]byte, error) {
	reveal := []byte(fmt.Sprintf("%v;%v", string(revealBid), string(revealNonce)))

	hashFactory := crypto.NewSha256Factory()
	h := hashFactory.New()
	_, err := h.Write(reveal)
	if err != nil {
		return nil, xerrors.Errorf("leaf node failed: %v", err)
	}

	return h.Sum(nil), nil
}
