package wallet

import (
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/pkg/errors"
)

const (
	// SigHashBitcoinCash is the (mandatory) sighash flag
	// for bitcoin cash which activates BIP143 sig-hashing.
	SigHashBitcoinCash = 0x40
)

// validSignature is an internal structure for capturing
// the fields of a valid signature
type validSignature struct {
	pubKey *PublicKeyInfo
	sig    *TxSignature
	hash   []byte
}

// parsePubKeyAndSig is a helper function reused between
// the various CheckerInterface::CheckSig implementations
func parsePubKeyAndSig(vchPubKey []byte, vchSig []byte) (*PublicKeyInfo, *TxSignature, error) {
	pubKey, err := ParsePublicKeyInfo(vchPubKey)
	if err != nil {
		return nil, nil, err
	}

	txSig, err := ParseTxSignature(vchSig)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, txSig, nil
}

// checkTxSig is a helper function reused between
// the various CheckerInterface::CheckSig implementations
func checkTxSig(txSig *TxSignature, pubKey *PublicKeyInfo, hash []byte) (*validSignature, error) {
	if txSig.Signature.Verify(hash, pubKey.Key) {
		return &validSignature{
			pubKey: pubKey,
			sig:    txSig,
			hash:   hash,
		}, nil
	}

	return nil, errors.New("Invalid signature")
}

// bitcoinChecker implements CheckerInterface for the bitcoin network
type bitcoinChecker struct {
	tx        *wire.MsgTx
	nIn       int
	amount    int64
	sigHashes *txscript.TxSigHashes
}

// GetSigHash returns a valid sighash for the bitcoin network
func (c *bitcoinChecker) GetSigHash(script []byte, hashType txscript.SigHashType, sigVersion int) ([]byte, error) {
	var err error
	if sigVersion == 1 {
		return txscript.CalcWitnessSigHash(script, c.sigHashes, hashType, c.tx, c.nIn, c.amount)
	}

	var pops []parsedOpcode
	pops, err = parseScript(script)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse script for sighash")
	}
	hash := CalcSignatureHash(pops, hashType, c.tx, c.nIn)
	return hash, nil
}

// CheckSig implements signature checking on the bitcoin network
func (c *bitcoinChecker) CheckSig(script []byte, vchPubKey []byte, vchSig []byte,
	sigVersion int) (*validSignature, error) {
	pubKey, txSig, err := parsePubKeyAndSig(vchPubKey, vchSig)
	if err != nil {
		return nil, errors.Wrap(err, "checked failed to parse pubkey/sig")
	}

	hash, err := c.GetSigHash(script, txSig.HashType, sigVersion)
	if err != nil {
		return nil, errors.Wrap(err, "checked failed to create sighash")
	}

	return checkTxSig(txSig, pubKey, hash)
}

type bitcoinCashChecker struct {
	tx        *wire.MsgTx
	nIn       int
	amount    int64
	sigHashes *txscript.TxSigHashes
}

// GetSigHash operation for bitcoin cash
func (c *bitcoinCashChecker) GetSigHash(script []byte, hashType txscript.SigHashType, sigVersion int) ([]byte, error) {
	if sigVersion != 0 {
		return nil, errors.New("Invalid sigVersion - must be 0 on bitcoin cash")
	}

	var err error
	if (hashType & SigHashBitcoinCash) > 0 {
		return txscript.CalcWitnessSigHash(script, c.sigHashes, hashType, c.tx, c.nIn, c.amount)
	}

	var pops []parsedOpcode
	pops, err = parseScript(script)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse script for sighash")
	}
	hash := CalcSignatureHash(pops, hashType, c.tx, c.nIn)
	return hash, nil
}

// CheckSig operation for bitcoin cash
func (c *bitcoinCashChecker) CheckSig(script []byte, vchPubKey []byte, vchSig []byte,
	sigVersion int) (*validSignature, error) {
	pubKey, txSig, err := parsePubKeyAndSig(vchPubKey, vchSig)
	if err != nil {
		return nil, errors.Wrap(err, "checker failed to parse pubkey/sig")
	}

	hash, err := c.GetSigHash(script, txSig.HashType, sigVersion)
	if err != nil {
		return nil, errors.Wrap(err, "checker failed to create sighash")
	}

	return checkTxSig(txSig, pubKey, hash)
}

// CheckerInterface exposes an interface for operations
// related to a transaction inputs signature
type CheckerInterface interface {
	// GetSigHash returns the signature hash given some input params
	GetSigHash(script []byte, hashType txscript.SigHashType, sigVersion int) ([]byte, error)

	// CheckSig verifies a signature given some input params
	CheckSig(script []byte, vchPubKey []byte, vchSig []byte, sigVersion int) (*validSignature, error)
}

// BitcoinCheckerCreator is a factory function, that produces a CheckerInterface
// for the Bitcoin network.
func BitcoinCheckerCreator(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, nIn int, value int64) (CheckerInterface, error) {
	if nIn < 0 || nIn > len(tx.TxIn)-1 {
		return nil, errors.New("no input at this index")
	}

	return &bitcoinChecker{
		tx:        tx,
		sigHashes: sigHashes,
		nIn:       nIn,
		amount:    value,
	}, nil
}

// BitcoinCashCheckerCreator is a factory function, that produces a CheckerInterface
// for the Bitcoin Cash network. The difference is that bitcoin cash triggers
// bip143 sighashing based on sighash flags, instead of sign script type.
func BitcoinCashCheckerCreator(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, nIn int, value int64) (CheckerInterface, error) {
	if nIn < 0 || nIn > len(tx.TxIn)-1 {
		return nil, errors.New("no input at this index")
	}

	return &bitcoinCashChecker{
		tx:        tx,
		sigHashes: sigHashes,
		nIn:       nIn,
		amount:    value,
	}, nil
}
