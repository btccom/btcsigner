package wallet

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/fastsha256"
)

// GetP2SHScriptPubKey takes a redeemScript, and returns the scriptPubKey
// as a byte slice
func GetP2SHScriptPubKey(rs []byte, params *chaincfg.Params) ([]byte, error) {
	addr, err := btcutil.NewAddressScriptHash(rs, params)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(addr)
}

// GetP2WSHWitnessProgram computes the sha256 hash
// of the provided witness script and encodes this
// into a segwit v0 p2wsh witness program.
func GetP2WSHWitnessProgram(ws []byte) ([]byte, error) {
	scriptHash := fastsha256.Sum256(ws)
	wp := []byte{0x00, 0x20}
	wp = append(wp, scriptHash[:]...)

	return wp, nil
}

// BaseInput is a convenience function taking a hex string for
// the scriptPubKey, creates a bare scriptPubKey txOut, and
// initializes the InputSignData.
func BaseInput(txOutValue int64, spkStr string) (*InputSignData, error) {
	spk, err := hex.DecodeString(spkStr)
	if err != nil {
		return nil, err
	}

	txOut := wire.NewTxOut(txOutValue, spk)

	return &InputSignData{
		TxOut: txOut,
	}, nil
}

// P2SHInput is a convenience function taking a hex string for
// the REDEEMSCRIPT, creates the associated P2SH script and txOut,
// and initializes the InputSignData
func P2SHInput(txOutValue int64, rsStr string, params *chaincfg.Params) (*InputSignData, error) {
	rs, err := hex.DecodeString(rsStr)
	if err != nil {
		return nil, err
	}

	spk, err := GetP2SHScriptPubKey(rs, params)
	if err != nil {
		return nil, err
	}

	txOut := wire.NewTxOut(txOutValue, spk)

	return &InputSignData{
		TxOut:        txOut,
		RedeemScript: rs,
	}, nil
}

// P2WSHInput is a convenience function taking a hex string for
// the WITNESS SCRIPT, creates the associated P2WSH script and txOut,
// and initializes the InputSignData
func P2WSHInput(txOutValue int64, wsStr string) (*InputSignData, error) {
	ws, err := hex.DecodeString(wsStr)
	if err != nil {
		return nil, err
	}

	wp, err := GetP2WSHWitnessProgram(ws)
	if err != nil {
		return nil, err
	}

	txOut := wire.NewTxOut(txOutValue, wp)

	return &InputSignData{
		TxOut:         txOut,
		WitnessScript: ws,
	}, nil
}

// P2SHP2WSHInput is a convenience function taking a hex string for
// the WITNESS SCRIPT, creates the associated P2SH redeemScript (a P2WSH
// witness program), creates the associated P2SH scriptPubKey and txOUt,
// and initializes the InputSignData
func P2SHP2WSHInput(txOutValue int64, wsStr string, params *chaincfg.Params) (*InputSignData, error) {
	ws, err := hex.DecodeString(wsStr)
	if err != nil {
		return nil, err
	}

	signType := txscript.GetScriptClass(ws)
	if !CanSignType(signType) {
		return nil, err
	}

	wp, err := GetP2WSHWitnessProgram(ws)
	if err != nil {
		return nil, err
	}

	p2shScript, err := GetP2SHScriptPubKey(wp, params)
	if err != nil {
		return nil, err
	}

	txOut := wire.NewTxOut(txOutValue, p2shScript)

	return &InputSignData{
		TxOut:         txOut,
		RedeemScript:  wp,
		WitnessScript: ws,
	}, nil
}
