// Package auction implements a closed-bid auction contract
package auction

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.dedis.ch/dela"
	"go.dedis.ch/dela/contracts/value"
	"go.dedis.ch/dela/core/access"
	"go.dedis.ch/dela/core/execution"
	"go.dedis.ch/dela/core/execution/native"
	"go.dedis.ch/dela/core/store"
	"go.dedis.ch/dela/crypto"
	"golang.org/x/xerrors"
)

// Argument ENUM
const (
	BidLengthKey     string = "auction:bid_length"
	RevealLengthKey         = "auction:reveal_length"
	OwnerKey                = "auction:owner"
	BiddersKey              = "auction:bidders"
	RevealersKey            = "auction:revealers"
	HighestBidderKey        = "auction:highest_bidder"
	HighestBidKey           = "auction:highest_bid"
	BlockNumberKey          = "auction:block_number"
	ListDelimiter           = ";"
	BidKey                  = "bid"
	DepositKey              = "deposit"
	RevealBidKey            = "reveal:bid"
	RevealNonceKey          = "reveal:nonce"
)

// commands defines the commands of the auction contract. This interface helps in
// testing the contract.
type commands interface {
	init(snap store.Snapshot, step execution.Step) error
	bid(snap store.Snapshot, step execution.Step) error
	reveal(snap store.Snapshot, step execution.Step) error
	selectWinner(snap store.Snapshot, step execution.Step) error
}

const (
	// ContractName is the name of the contract.
	ContractName = "go.dedis.ch/dela.Auction"

	// INIT
	// InitBidLengthArg is the argument's name in the transaction that contains the
	// bid length.
	InitBidLengthArg = "value:initBidLength"
	// InitRevealLengthArg is the argument's name in the transaction that contains the
	// reveal length.
	InitRevealLengthArg = "value:initRevealLength"

	// BID
	// BidArg is the argument's name in the transaction that contains the
	// Hash(bid, nonce).
	BidArg = "value:bid"
	// BidDepositArg is the argument's name in the transaction that contains the
	// Deposit for the bid.
	BidDepositArg = "value:bid_deposit"

	// REVEAL
	// RevealBidArg is the argument's name in the transaction that contains the
	// bid to reveal.
	RevealBidArg = "value:revealBid"
	// RevealNonceArg is the argument's name in the transaction that contains
	// the nonce to reveal
	RevealNonceArg = "value:revealNonce"

	// CmdArg is the argument's name to indicate the kind of command we want to
	// run on the contract. Should be one of the Command type.
	CmdArg = "value:command"

	// credentialAllCommand defines the credential command that is allowed to
	// perform all commands.
	credentialAllCommand = "all"
)

// Command defines a type of command for the value contract
type Command string

const (
	// CmdBid defines the command to initialize Auction SC Values
	CmdInit Command = "INIT"

	// CmdBid defines the command to make a bid
	CmdBid Command = "BID"

	// CmdReveal defines the command to reveal a bid
	CmdReveal Command = "REVEAL"

	// CmdWinner defines the command to select the auction winner
	CmdWinner Command = "SELECTWINNER"
)

// NewCreds creates new credentials for an auction contract execution. We might
// want to use in the future a separate credential for each command.
func NewCreds(id []byte) access.Credential {
	return access.NewContractCreds(id, ContractName, credentialAllCommand)
}

// RegisterContract registers the auction contract to the given execution service.
func RegisterContract(exec *native.Service, c Contract) {
	exec.Set(ContractName, c)
}

// Contract is a smart contract that allows for closed-bid auctions
//
// - implements native.Contract
type Contract struct {
	// store is used to store/retrieve data
	store value.Contract

	// access is the access control service managing this smart contract
	access access.Service

	// accessKey is the access identifier allowed to use this smart contract
	accessKey []byte

	// Used to hash reveals to check against bids
	hashFactory crypto.HashFactory

	// cmd provides the commands that can be executed by this smart contract
	cmd commands

	// printer is the output used by the READ and LIST commands
	printer io.Writer
}

// NewContract creates a new Auction contract
func NewContract(aKey []byte, srvc access.Service) Contract {
	// Create new contract
	contract := Contract{
		store:       value.NewContract(aKey, srvc),
		access:      srvc,
		hashFactory: crypto.NewSha256Factory(),
		accessKey:   aKey,
		printer:     infoLog{},
	}

	contract.cmd = auctionCommand{Contract: &contract}

	return contract
}

// Execute implements native.Contract. It runs the appropriate command.
func (c Contract) Execute(snap store.Snapshot, step execution.Step) error {
	creds := NewCreds(c.accessKey)

	err := c.access.Match(snap, creds, step.Current.GetIdentity())
	if err != nil {
		return xerrors.Errorf("identity not authorized: %v (%v)",
			step.Current.GetIdentity(), err)
	}

	cmd := step.Current.GetArg(CmdArg)
	if len(cmd) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", CmdArg)
	}

	switch Command(cmd) {
	case CmdInit:
		err := c.cmd.init(snap, step)
		if err != nil {
			return xerrors.Errorf("failed to INIT: %v", err)
		}
	case CmdBid:
		err := c.cmd.bid(snap, step)
		if err != nil {
			return xerrors.Errorf("failed to BID: %v", err)
		}
	case CmdReveal:
		err := c.cmd.reveal(snap, step)
		if err != nil {
			return xerrors.Errorf("failed to REVEAL: %v", err)
		}
	default:
		return xerrors.Errorf("unknown command: %s", cmd)
	}

	return nil
}

// auctionCommand implements the commands of the auction contract
//
// - implements commands
type auctionCommand struct {
	*Contract
}

// ############################################################################
// ########################## HELPER FUNCTIONS ################################
// ############################################################################

// HashReveal hashes "revealBid;revealNonce" string
func (c Contract) HashReveal(revealBid []byte, revealNonce []byte) ([]byte, error) {
	reveal := []byte(fmt.Sprintf("%v;%v", string(revealBid), string(revealNonce)))

	h := c.hashFactory.New()
	_, err := h.Write(reveal)
	if err != nil {
		return nil, xerrors.Errorf("leaf node failed: %v", err)
	}

	return h.Sum(nil), nil
}

// Gets bid length
// Used to determine if in bidding period
func getBidLength(snap store.Snapshot) (int, error) {
	// Get Bid Length
	key := []byte(BidLengthKey)
	bidLengthByte, err := snap.Get(key)
	if err != nil {
		return -1, xerrors.Errorf("failed to get bid length", err)
	}

	// Convert Bid Length to int
	bidLength, err := strconv.Atoi(string(bidLengthByte))
	if err != nil {
		return -1, xerrors.Errorf("failed to convert bid_length to int: %v. Error: %v", err)
	}

	return bidLength, nil
}

// Gets reveal length
// Used to determine if auction in reveal period
func getRevealLength(snap store.Snapshot) (int, error) {
	// Get Bid Length
	key := []byte(RevealLengthKey)
	revealLengthByte, err := snap.Get(key)
	if err != nil {
		return -1, xerrors.Errorf("failed to get bid length", err)
	}

	// Convert Bid Length to int
	revealLength, err := strconv.Atoi(string(revealLengthByte))
	if err != nil {
		return -1, xerrors.Errorf("failed to convert reveal_length to int: %v. Error: %v", err)
	}

	return revealLength, nil
}

// Gets the current block number
// Block number is defined as the number of bid or reveal tx that have taken place
func getBlockNumber(snap store.Snapshot) (int, error) {
	// Get block number from database
	key := []byte(BlockNumberKey)
	blockNumberByte, err := snap.Get(key)
	if err != nil {
		return -1, xerrors.Errorf("failed to get block_number", err)
	}

	// Convert block number to int
	// Convert reveal to integer
	blockNumber, err := strconv.Atoi(string(blockNumberByte))
	if err != nil {
		return -1, xerrors.Errorf("failed to convert block_number to int: %v. Error: %v", err)
	}

	return blockNumber, nil
}

// Used to increment block number after bid or reveal tx
func incBlockNumber(snap store.Snapshot) error {
	// Get block number from database
	blockNumber, err := getBlockNumber(snap)
	if err != nil {
		return xerrors.Errorf("failed to get block number: %v. Error: %v", err)
	}

	// Inc blockNumber
	blockNumber = blockNumber + 1
	err = snap.Set([]byte(BlockNumberKey), []byte(strconv.Itoa(blockNumber)))
	if err != nil {
		return xerrors.Errorf("failed to set increment block number: %v", err)
	}

	return nil
}

// Checks if contract is in bidding period
func isValidBidPeriod(snap store.Snapshot) (bool, error) {
	blockNumber, err := getBlockNumber(snap)
	if err != nil {
		return false, err
	}

	bidPeriod, err := getBidLength(snap)
	if err != nil {
		return false, err
	}

	if blockNumber < bidPeriod {
		return true, nil
	}

	return false, nil
}

// Checks if contract is in reveal period
func isValidRevealPeriod(snap store.Snapshot) (bool, error) {
	blockNumber, err := getBlockNumber(snap)
	if err != nil {
		return false, err
	}

	// Get bid and reveal periods
	bidPeriod, err := getBidLength(snap)
	if err != nil {
		return false, err
	}
	revealPeriod, err := getRevealLength(snap)
	if err != nil {
		return false, err
	}

	// Check if blockNumber between bid and reveal periods
	if blockNumber >= bidPeriod && blockNumber < bidPeriod+revealPeriod {
		return true, nil
	}

	return false, nil
}

// Checks if auction is over
// Used to determine if auction owner can selectWinner
func isAuctionOver(snap store.Snapshot) (bool, error) {
	blockNumber, err := getBlockNumber(snap)
	if err != nil {
		return false, err
	}

	// Get bid and reveal periods
	bidPeriod, err := getBidLength(snap)
	if err != nil {
		return false, err
	}
	revealPeriod, err := getRevealLength(snap)
	if err != nil {
		return false, err
	}

	// Check if blockNumber between bid and reveal periods
	if blockNumber >= bidPeriod+revealPeriod {
		return true, nil
	}

	return false, nil
}

func isAuctionOwner(snap store.Snapshot, pk []byte) (bool, error) {
	// Get auction owner
	owner, err := snap.Get([]byte(OwnerKey))
	if err != nil {
		return false, xerrors.Errorf("owner not found in store")
	}

	// Check if pk matches auction owner
	if string(owner) == string(pk) {
		return true, nil
	} else {
		return false, nil
	}
}

// ############################################################################
// ############################ INIT FUNCTIONS ################################
// ############################################################################

// init implements commands. It performs the INIT command
// Auction owner initialises bid_length, reveal_length, maximum_bid
func (c auctionCommand) init(snap store.Snapshot, step execution.Step) error {
	// Obtain public key from this txn
	pub_key, err := step.Current.GetIdentity().MarshalText()
	if err != nil {
		return xerrors.Errorf("public key not found in tx arg")
	}

	// Obtain initBidLength from auctionCommand
	initBidLength := step.Current.GetArg(InitBidLengthArg)
	if len(initBidLength) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", InitBidLengthArg)
	}
	// Obtain initRevealLength from auctionCommand
	initRevealLength := step.Current.GetArg(InitRevealLengthArg)
	if len(initRevealLength) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", InitRevealLengthArg)
	}

	// Store pub_key as auction owner
	//   (auction:owner)
	keyAuctionOwner := []byte(OwnerKey)
	valAuctionOwner := pub_key
	err = snap.Set(keyAuctionOwner, valAuctionOwner)
	if err != nil {
		return xerrors.Errorf("failed to set owner: %v", err)
	}

	// Store bid length arg
	// 	(auction:bid_length)
	keyBidLength := []byte(BidLengthKey)
	valBidLength := initBidLength
	err = snap.Set(keyBidLength, valBidLength)
	if err != nil {
		return xerrors.Errorf("failed to set bid_length: %v", err)
	}
	// Store reveal length arg
	// 	(auction:reveal_length)
	keyRevealLength := []byte(RevealLengthKey)
	valRevealLength := initRevealLength
	err = snap.Set(keyRevealLength, valRevealLength)
	if err != nil {
		return xerrors.Errorf("failed to set reveal_length: %v", err)
	}
	// Create empty byte array for bidders
	err = snap.Set([]byte(BiddersKey), []byte(""))
	if err != nil {
		return xerrors.Errorf("failed to set bidders array: %v", err)
	}
	// Create empty byte array for revealers
	err = snap.Set([]byte(RevealersKey), []byte(""))
	if err != nil {
		return xerrors.Errorf("failed to set revealers array: %v", err)
	}
	// Initialise highest bidder
	err = snap.Set([]byte(HighestBidderKey), []byte("-1"))
	if err != nil {
		return xerrors.Errorf("failed to set highest bidder: %v", err)
	}
	// Initialise highest bid
	err = snap.Set([]byte(HighestBidKey), []byte("-1"))
	if err != nil {
		return xerrors.Errorf("failed to set highest bid: %v", err)
	}
	// Initialise block number
	err = snap.Set([]byte(BlockNumberKey), []byte("0"))
	if err != nil {
		return xerrors.Errorf("failed to set block number: %v", err)
	}

	dela.Logger.Info().Str("contract", ContractName).Msgf("setting %x=%s, %s=%s", keyBidLength, valBidLength, keyRevealLength, valRevealLength)

	return nil
}

// ############################################################################
// ############################# BID FUNCTIONS ################################
// ############################################################################

func getBid(snap store.Snapshot, bidder []byte) ([]byte, error) {
	// Get reveal bid from database
	bidKey := []byte(fmt.Sprintf("%s:%s", string(bidder), BidKey))
	bid, err := snap.Get(bidKey)
	if err != nil {
		return []byte{}, xerrors.Errorf("failed to get reveal bid", err)
	}

	return bid, nil
}

// storeBid stores a bid from a bidder
func storeBid(snap store.Snapshot, bidder []byte, bid []byte) error {
	key := []byte(fmt.Sprintf("%s:%s", string(bidder), "bid"))
	val := bid
	err := snap.Set(key, val)
	if err != nil {
		return xerrors.Errorf("failed to set bid: %v", err)
	}

	return nil
}

// storeBidder stores a bidder in a bidders list
func storeBidder(snap store.Snapshot, bidder []byte) error {
	// Get bidders list
	key := []byte(BiddersKey)
	bidders_list, err := snap.Get(key)
	if err != nil {
		return xerrors.Errorf("failed to get bidders list", err)
	}

	// Add bidder to bidders list
	bidders_list = []byte(fmt.Sprintf("%s%s;", string(bidders_list), string(bidder)))
	err = snap.Set(key, bidders_list)
	if err != nil {
		return xerrors.Errorf("failed to set bidders list", err)
	}

	return nil
}

// getBiddersList gets list of bidders in string format
func getBiddersList(snap store.Snapshot) ([]string, error) {
	// Get bidders list
	key := []byte(BiddersKey)
	bidders_list, err := snap.Get(key)
	if err != nil {
		return []string{}, xerrors.Errorf("failed to get bidders list", err)
	}

	// Convert bidders_list to array of string values
	bidders := strings.Split(string(bidders_list), ListDelimiter)
	return bidders, nil
}

// bid implements commands. It performs the BID command
// User bids Hash(bid, nonce)
func (c auctionCommand) bid(snap store.Snapshot, step execution.Step) error {
	// Check if bid period
	isBidPeriod, err := isValidBidPeriod(snap)
	if err != nil {
		return err
	}
	if !isBidPeriod {
		return xerrors.Errorf("Not valid bid period")
	}

	// Obtain public key from this txn
	pub_key, err := step.Current.GetIdentity().MarshalText()
	if err != nil {
		return xerrors.Errorf("public key not found in tx argument")
	}

	// Check bid/deposit from auctionCommand
	bid := step.Current.GetArg(BidArg)
	if len(bid) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", BidArg)
	}
	deposit := step.Current.GetArg(BidDepositArg)
	if len(deposit) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", BidDepositArg)
	}

	// Store bid as (pub_key:bid, bid)
	err = storeBid(snap, pub_key, bid)
	if err != nil {
		return err
	}

	// Store bidder as bidder: [bidder1; ...; bidderN;]
	storeBidder(snap, pub_key)
	if err != nil {
		return err
	}

	// Store deposit as (pub_key:deposit, deposit)
	// err = storeDeposit(snap, pub_key, deposit)
	// if err != nil {
	// 	return err
	// }

	// Increment block number
	err = incBlockNumber(snap)
	if err != nil {
		return err
	}

	dela.Logger.Info().Str("contract", ContractName).Msgf("setting %v=%v", pub_key, bid)

	return nil
}

// ############################################################################
// ########################### REVEAL FUNCTIONS ###############################
// ############################################################################

// storeBid stores a bid from a bidder
func storeReveal(snap store.Snapshot, revealer []byte, bid []byte, nonce []byte) error {
	// Set reveal:bid value
	key := []byte(fmt.Sprintf("%s:%s", string(revealer), RevealBidKey))
	val := bid
	err := snap.Set(key, val)
	if err != nil {
		return xerrors.Errorf("failed to set revealBid value: %v", err)
	}

	// Set reveal:nonce value
	key = []byte(fmt.Sprintf("%s:%s", string(revealer), RevealNonceKey))
	val = nonce
	err = snap.Set(key, val)
	if err != nil {
		return xerrors.Errorf("failed to set revealNonce value: %v", err)
	}

	return nil
}

// storeRevealer stores a revealer in the revealers list
func storeRevealer(snap store.Snapshot, revealer []byte) error {
	// Get revealers list
	key := []byte(RevealersKey)
	revealers_list, err := snap.Get(key)
	if err != nil {
		return xerrors.Errorf("failed to get revealers list", err)
	}

	// Add revealer to revealers list
	revealers_list = []byte(fmt.Sprintf("%s%s;", string(revealers_list), string(revealer)))
	err = snap.Set(key, revealers_list)
	if err != nil {
		return xerrors.Errorf("failed to set revealers list", err)
	}

	return nil
}

func getReveal(snap store.Snapshot, revealer []byte) ([]byte, []byte, error) {
	// Get reveal bid from database
	revealBidKey := []byte(fmt.Sprintf("%s:%s", string(revealer), RevealBidKey))
	revealBid, err := snap.Get(revealBidKey)
	if err != nil {
		return []byte{}, []byte{}, xerrors.Errorf("failed to get reveal bid", err)
	}
	// Get reveal nonce from database
	revealNonceKey := []byte(fmt.Sprintf("%s:%s", string(revealer), RevealNonceKey))
	revealNonce, err := snap.Get(revealNonceKey)
	if err != nil {
		return []byte{}, []byte{}, xerrors.Errorf("failed to get reveal nonce", err)
	}

	return revealBid, revealNonce, nil
}

// getRevealersList gets list of revealers in string format
func getRevealersList(snap store.Snapshot) ([]string, error) {
	// Get bidders list
	key := []byte(RevealersKey)
	revealers_list, err := snap.Get(key)
	if err != nil {
		return []string{}, xerrors.Errorf("failed to get revealers list", err)
	}

	// Convert bidders_list to array of string values
	bidders := strings.Split(string(revealers_list), ListDelimiter)
	bidders = bidders[:len(bidders)-1]
	return bidders, nil
}

// reveal implements commands. It performs the REVEAL command
// User reveals bid, nonce
func (c auctionCommand) reveal(snap store.Snapshot, step execution.Step) error {
	// Check if reveal period
	isRevealPeriod, err := isValidRevealPeriod(snap)
	if err != nil {
		return err
	}
	if !isRevealPeriod {
		return xerrors.Errorf("Not valid reveal period")
	}

	// Obtain public key from this txn
	pub_key, err := step.Current.GetIdentity().MarshalText()
	if err != nil {
		return xerrors.Errorf("public key not found in tx argument")
	}

	// Obtain revealBid from auctionCommand
	revealBid := step.Current.GetArg(RevealBidArg)
	if len(revealBid) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", RevealBidArg)
	}

	// Obtain revealNonce from auctionCommand
	revealNonce := step.Current.GetArg(RevealNonceArg)
	if len(revealNonce) == 0 {
		return xerrors.Errorf("'%s' not found in tx arg", RevealNonceArg)
	}

	// Hash Reveal
	revealHash, err := c.HashReveal(revealBid, revealNonce)
	// Get bid
	bid, err := getBid(snap, pub_key)
	if err != nil {
		return xerrors.Errorf(("No bid from user '%s"), pub_key)
	}
	// Check that bid matches reveal
	comparison := bytes.Compare(bid, revealHash)
	if comparison != 0 {
		return xerrors.Errorf("Bid does not match reveal hash")
	}

	// Store reveal
	err = storeReveal(snap, pub_key, revealBid, revealNonce)
	if err != nil {
		return err
	}

	// Store revealer
	err = storeRevealer(snap, pub_key)
	if err != nil {
		return err
	}

	// Increment block number
	err = incBlockNumber(snap)
	if err != nil {
		return err
	}

	dela.Logger.Info().Str("contract", ContractName).Msgf("setting %x=(%s, %s)", pub_key, revealBid, revealNonce)

	return nil
}

// selectWinner implements commands. It performs the SELECTWINNER command
// Auction SC searches for the highest reveal, ensures it matches bid, and selects that winner
func (c auctionCommand) selectWinner(snap store.Snapshot, step execution.Step) error {
	// Ensure tx pk is contract owner
	pub_key, err := step.Current.GetIdentity().MarshalText()
	if err != nil {
		return xerrors.Errorf("Could not obtain pk from tx")
	}
	isOwner, err := isAuctionOwner(snap, pub_key)
	if !isOwner {
		return xerrors.Errorf("selectWinner not called by contract owner")
	}

	// Ensure auction is complete
	isAuctionOver, err := isAuctionOver(snap)
	if !isAuctionOver {
		return xerrors.Errorf("Auction is not over")
	}

	// Get string of revealers, create list from string
	revealers, err := getRevealersList(snap)
	if err != nil {
		return err
	}
	fmt.Println("Revealers: ", revealers)

	// Iterate through reveals, selecting highest bidder
	highestBidder := []byte{}
	highestBid := -1
	i := 1
	for _, thisRevealer := range revealers {
		fmt.Println("This Revealer iteration: ", i)
		revealer := []byte(thisRevealer)
		// FOR TESTING
		fmt.Println("This Revealer: ", thisRevealer)
		// Get reveal
		revealBid := []byte{0}
		revealBid, _, err := getReveal(snap, []byte(revealer))
		if err != nil {
			return xerrors.Errorf("failed to get reveal for revealer: %v. Error: %v", revealer, err)
		}
		// FOR TESTING
		fmt.Println("This Reveal Bid: ", revealBid)
		// Convert reveal to integer
		revealBidInt, err := strconv.Atoi(string(revealBid))
		if err != nil {
			return xerrors.Errorf("failed to convert reveal bid to int: %v. Error: %v", err)
		}
		// Check if highest bid
		if revealBidInt > highestBid {
			highestBidder = revealer
			highestBid = revealBidInt
		}

		i += 1
	}

	// Now we have the highestBidder, store highestBidder
	err = snap.Set([]byte("auction:highest_bidder"), []byte(highestBidder))
	if err != nil {
		return xerrors.Errorf("failed to set highest bidder: %v", err)
	}
	// Store highestBid
	err = snap.Set([]byte("auction:highest_bid"), []byte(strconv.Itoa(highestBid)))
	if err != nil {
		return xerrors.Errorf("failed to set highest bidder: %v", err)
	}

	// TODO: REFUND LOSERS

	// dela.Logger.Info().Str("contract", ContractName).Msgf("setting Highest Bidder=%s", highestBidder)

	return nil
}

// infoLog defines an output using zerolog
//
// - implements io.writer
type infoLog struct{}

func (h infoLog) Write(p []byte) (int, error) {
	dela.Logger.Info().Msg(string(p))

	return len(p), nil
}
