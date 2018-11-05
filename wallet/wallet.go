package wallet

import (
	"github.com/btccom/btcsigner/bip32util"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
)

// SignatureProvider is a contract whereby implementations
// accept an address (to aid in loading the key), and a message,
// and will return a public key, signature, or an error
type SignatureProvider interface {
	Sign(btcutil.Address, []byte) (*btcec.PublicKey, *btcec.Signature, bool, error)
}

// Wallet defines a general contract for a wallet backend.
// It must provide a method that generates a SignatureProvider
// for a certain wallet + keyOrigin pair.
type Wallet interface {
	// GetSigner returns a SignatureProvider for the walletID/key origin
	GetSigner(walletID int64, key *KeyOrigin) (SignatureProvider, error)
}

// KeyOrigin contains information about how to retrieve the key.
// It currently supports BIP32 paths for Bip32Wallet provided keys,
// and HsmKey identifier HsmWallet provided keys
type KeyOrigin struct {
	Bip32  *bip32util.Path
	HsmKey string
}
