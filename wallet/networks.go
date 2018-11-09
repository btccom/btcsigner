package wallet

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/pkg/errors"
)

const (
	// NetBtc is the constant for the bitcoin network
	NetBtc = "btc"

	// NetBtcTest = is the constant for the bitcoin testnet network
	NetBtcTest = "tbtc"

	// NetBtcRegtest is the constant for the bitcoin regtest network
	NetBtcRegtest = "rbtc"

	// NetBch is the constant for the bitcoin cash network
	NetLtc = "ltc"

	// NetLtcTest is the constant for the bitcoin cash testnet network
	NetLtcTest = "tltc"

	// NetLtcRegtest is the constant for the bitcoin cash regtest network
	NetLtcRegtest = "rltc"

	// NetBch is the constant for the bitcoin cash network
	NetBch = "bch"

	// NetBchTest is the constant for the bitcoin cash testnet network
	NetBchTest = "tbch"

	// NetBchRegtest is the constant for the bitcoin cash regtest network
	NetBchRegtest = "rbch"
)

// CheckNetwork validates that the network is valid
func CheckNetwork(network string) (string, error) {
	switch network {
	case NetBtc, NetBtcTest, NetBtcRegtest,
		NetLtc, NetLtcTest, NetLtcRegtest,
		NetBch, NetBchTest, NetBchRegtest:
		return network, nil
	default:
		return "", errors.New("Network is invalid")
	}
}

// Network captures customizations which differ
// from network to network. It covers the obvious
// chainParams, but also has a network specific
// CheckerCreator (for signature validation), and
// DefaultHashType for signing.
type Network struct {

	// Params holds the networks chain params
	Params *chaincfg.Params

	// CheckerCreator holds a function implementing
	// the CheckerCreator interface, responsible
	// for producing a struct for sighashing, and
	// sig validation.
	CheckerCreator CheckerCreator

	// DefaultHashType differs on some networks, so
	// the default is held in this field.
	DefaultHashType txscript.SigHashType

	// SegwitEnabled toggles whether segwit support is
	// active
	SegwitEnabled bool
}

var (
	// BtcNetwork defines the behaviour on the Bitcoin network
	BtcNetwork = &Network{
		Params:          &chaincfg.MainNetParams,
		CheckerCreator:  BitcoinCheckerCreator,
		DefaultHashType: txscript.SigHashAll,
		SegwitEnabled:   true,
	}

	// BtcTestNetwork defines the behaviour on the Bitcoin testnet
	BtcTestNetwork = &Network{
		Params:          &chaincfg.TestNet3Params,
		CheckerCreator:  BitcoinCheckerCreator,
		DefaultHashType: txscript.SigHashAll,
		SegwitEnabled:   true,
	}

	// BtcRegtestNetwork defines the behaviour on the Bitcoin regtest network
	BtcRegtestNetwork = &Network{
		Params:          &chaincfg.RegressionNetParams,
		CheckerCreator:  BitcoinCheckerCreator,
		DefaultHashType: txscript.SigHashAll,
		SegwitEnabled:   true,
	}

	// LtcNetwork defines the behaviour on the Bitcoin Cash network
	LtcNetwork = &Network{
		Params:          &chaincfg.MainNetParams,
		CheckerCreator:  BitcoinCheckerCreator,
		DefaultHashType: txscript.SigHashAll,
		SegwitEnabled:   true,
	}

	// LtcTestNetwork defines the behaviour on the Bitcoin Cash testnet
	LtcTestNetwork = &Network{
		Params:          &chaincfg.TestNet3Params,
		CheckerCreator:  BitcoinCheckerCreator,
		DefaultHashType: txscript.SigHashAll,
		SegwitEnabled:   true,
	}

	// LtcRegtestNetwork defines the behavior on the Bitcoin Cash regtest network
	LtcRegtestNetwork = &Network{
		Params:          &chaincfg.RegressionNetParams,
		CheckerCreator:  BitcoinCheckerCreator,
		DefaultHashType: txscript.SigHashAll,
		SegwitEnabled:   true,
	}

	// BchNetwork defines the behaviour on the Bitcoin Cash network
	BchNetwork = &Network{
		Params:          &chaincfg.MainNetParams,
		CheckerCreator:  BitcoinCashCheckerCreator,
		DefaultHashType: txscript.SigHashAll | SigHashBitcoinCash,
		SegwitEnabled:   false,
	}

	// BchTestNetwork defines the behaviour on the Bitcoin Cash testnet
	BchTestNetwork = &Network{
		Params:          &chaincfg.TestNet3Params,
		CheckerCreator:  BitcoinCashCheckerCreator,
		DefaultHashType: txscript.SigHashAll | SigHashBitcoinCash,
		SegwitEnabled:   false,
	}

	// BchRegtestNetwork defines the behavior on the Bitcoin Cash regtest network
	BchRegtestNetwork = &Network{
		Params:          &chaincfg.RegressionNetParams,
		CheckerCreator:  BitcoinCashCheckerCreator,
		DefaultHashType: txscript.SigHashAll | SigHashBitcoinCash,
		SegwitEnabled:   false,
	}
)

// GetNetworkParams takes a network string shortcode
// and returns the *Network params
func GetNetworkParams(network string) (*Network, error) {
	switch network {
	case NetBtc:
		return BtcNetwork, nil
	case NetBtcTest:
		return BtcTestNetwork, nil
	case NetBtcRegtest:
		return BtcRegtestNetwork, nil
	case NetLtc:
		return LtcNetwork, nil
	case NetLtcTest:
		return LtcTestNetwork, nil
	case NetLtcRegtest:
		return LtcRegtestNetwork, nil
	case NetBch:
		return BchNetwork, nil
	case NetBchTest:
		return BchTestNetwork, nil
	case NetBchRegtest:
		return BchRegtestNetwork, nil
	}

	return nil, errors.New("Invalid network")
}
