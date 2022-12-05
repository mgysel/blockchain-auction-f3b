package controller

import (
	"go.dedis.ch/dela/cli"
	"go.dedis.ch/dela/cli/node"
	"go.dedis.ch/dela/contracts/auction"
	"go.dedis.ch/dela/core/access"
	"go.dedis.ch/dela/core/execution/native"
	"golang.org/x/xerrors"
)

// aKey is the access key used for the auction contract
var aKey = [32]byte{2}

// miniController is a CLI initializer to register the auction contract
//
// - implements node.Initializer
type miniController struct {
}

// NewController creates a new minimal controller for the auction contract.
func NewController() node.Initializer {
	return miniController{}
}

// SetCommands implements node.Initializer.
func (miniController) SetCommands(builder node.Builder) {
}

// OnStart implements node.Initializer. It registers the auction contract.
func (m miniController) OnStart(flags cli.Flags, inj node.Injector) error {
	var access access.Service
	err := inj.Resolve(&access)
	if err != nil {
		return xerrors.Errorf("failed to resolve access service: %v", err)
	}

	var exec *native.Service
	err = inj.Resolve(&exec)
	if err != nil {
		return xerrors.Errorf("failed to resolve native service: %v", err)
	}

	// NOTE: I NOW CREATE THE VALUE CONTRACT WITHIN THE AUCTION CONTRACT
	// Create and register value contract
	// valueContract := value.NewContract(aKey[:], access)
	// value.RegisterContract(exec, valueContract)

	// Create and register auction contract
	auctionContract := auction.NewContract(aKey[:], access)
	auction.RegisterContract(exec, auctionContract)

	return nil
}

// OnStop implements node.Initializer.
func (miniController) OnStop(inj node.Injector) error {
	return nil
}
