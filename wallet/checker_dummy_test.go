package wallet

import (
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/pkg/errors"
	_assert "github.com/stretchr/testify/require"
	"testing"
)

// dummyChecker implements CheckerInterface
type dummyChecker struct {
	tx        *wire.MsgTx
	nIn       int
	amount    int64
	sigHashes *txscript.TxSigHashes
}

// GetSigHash returns a valid sighash for the bitcoin network
func (c *dummyChecker) GetSigHash(script []byte, hashType txscript.SigHashType, sigVersion int) ([]byte, error) {
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

// CheckSig implements a dummy checksig operation for bitcoin
func (c *dummyChecker) CheckSig(script []byte, vchPubKey []byte, vchSig []byte,
	sigVersion int) (*validSignature, error) {
	pubKey, txSig, err := parsePubKeyAndSig(vchPubKey, vchSig)
	if err != nil {
		return nil, errors.Wrap(err, "checker failed to parse pubkey/sig")
	}
	hash, err := c.GetSigHash(script, txSig.HashType, sigVersion)
	if err != nil {
		return nil, errors.Wrap(err, "checker failed to create sighash")
	}
	return &validSignature{
		pubKey: pubKey,
		sig:    txSig,
		hash:   hash,
	}, nil
}

// DummyBitcoinCheckerCreator is a dummy bitcoinChecker that returns a
// validSignature so long as the pubkey/sig can be parsed. It does
// not verify signatures, so allows testing with dummy signature elements.
func DummyBitcoinCheckerCreator(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, nIn int, value int64) (CheckerInterface, error) {
	if nIn < 0 || nIn > len(tx.TxIn)-1 {
		return nil, errors.New("no input at this index")
	}

	return &dummyChecker{
		tx:        tx,
		sigHashes: sigHashes,
		nIn:       nIn,
		amount:    value,
	}, nil
}

func TestDummyCheckerCheckSigReturnsTrueAlways(t *testing.T) {
	params := &chaincfg.TestNet3Params

	spendTxID, err := chainhash.NewHashFromStr("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	_assert.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  *spendTxID,
					Index: 0,
				},
				SignatureScript: []byte{},
				Witness:         wire.TxWitness{},
				Sequence:        0xffffffff,
			},
		},
	}

	// Initalize public keys for tests
	pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
	_assert.NoError(t, err)

	pubKeyHashScript := addrToScript(t, pubKeyHashAddrFromBytes(t, pubKey1, params))

	spkData := &ScriptData{}
	err = spkData.Parse(pubKeyHashScript, params)
	_assert.NoError(t, err)

	prevTxOut := &wire.TxOut{
		Value:    12341234,
		PkScript: spkData.Script,
	}

	sig, err := hex.DecodeString("30440220432deba8c65c2e1411282ffe4975ed9697b7833a169070df50b2b9f43408f4000220049b8774d71b3a72dc1abeccfb8f7f58398955baf2201db5249514e8ef7409da01")
	_assert.NoError(t, err)

	sigHashes := txscript.NewTxSigHashes(tx)
	checker, err := DummyBitcoinCheckerCreator(tx, sigHashes, 0, prevTxOut.Value)
	_assert.NoError(t, err)

	validSig, err := checker.CheckSig(spkData.Script, pubKey1, sig, 0)
	_assert.NoError(t, err)
	_assert.IsType(t, validSignature{}, *validSig)

	serializedSig := validSig.sig.Serialize()
	_assert.True(t, bytes.Equal(sig, serializedSig))

	serializedKey, err := validSig.pubKey.Serialize()
	_assert.NoError(t, err)
	_assert.True(t, bytes.Equal(pubKey1, serializedKey))

	_assert.False(t, validSig.sig.Signature.Verify(validSig.hash, validSig.pubKey.Key))
}
