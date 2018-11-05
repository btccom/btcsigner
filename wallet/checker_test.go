package wallet

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	_assert "github.com/stretchr/testify/require"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const (
	btcDummy = "bitcoindummy"
	btc      = "bitcoin"
	bch      = "bitcoincash"
)

func TestParsePubKeyAndSig(t *testing.T) {
	// Initalize public keys for tests
	publicKey, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
	_assert.NoError(t, err)

	signature, err := hex.DecodeString("30440220432deba8c65c2e1411282ffe4975ed9697b7833a169070df50b2b9f43408f4000220049b8774d71b3a72dc1abeccfb8f7f58398955baf2201db5249514e8ef7409da01")
	_assert.NoError(t, err)

	empty := []byte(``)

	t.Run("invalid sigs are rejected", func(t *testing.T) {
		pub, sig, err := parsePubKeyAndSig(publicKey, empty)
		_assert.Nil(t, pub)
		_assert.Nil(t, sig)
		_assert.EqualError(t, err, "TxSignature too short")
	})

	t.Run("invalid keys are rejected", func(t *testing.T) {
		pub, sig, err := parsePubKeyAndSig(empty, signature)
		_assert.Nil(t, pub)
		_assert.Nil(t, sig)
		_assert.EqualError(t, err, "Invalid length of public key")
	})

	t.Run("returns values if parsable", func(t *testing.T) {
		pub, sig, err := parsePubKeyAndSig(publicKey, signature)
		_assert.NoError(t, err)
		_assert.IsType(t, PublicKeyInfo{}, *pub)
		_assert.IsType(t, TxSignature{}, *sig)
	})
}

func TestCheckerErrorConditions(t *testing.T) {
	fixtures := []struct {
		name    string
		creator CheckerCreator
	}{
		{
			name:    "dummy",
			creator: DummyBitcoinCheckerCreator,
		},
		{
			name:    "btc",
			creator: BitcoinCheckerCreator,
		},
		{
			name:    "bch",
			creator: BitcoinCashCheckerCreator,
		},
	}

	spendTxID, err := chainhash.NewHashFromStr("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	_assert.NoError(t, err)

	tx := &wire.MsgTx{
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  *spendTxID,
					Index: 0,
				},
			},
		},
	}

	var value int64 = 12341234
	invalidScript := []byte{0x01}
	for i := 0; i < len(fixtures); i++ {
		creator := fixtures[i].creator

		t.Run(fixtures[i].name+" invalid scripts cause problems for sighash", func(t *testing.T) {
			checker, err := creator(tx, txscript.NewTxSigHashes(tx), 0, value)
			_assert.NoError(t, err)

			hash, err := checker.GetSigHash(invalidScript, txscript.SigHashAll, 0)
			_assert.Error(t, err)
			_assert.True(t, strings.Contains(err.Error(), "failed to parse script for sighash"))
			_assert.Nil(t, hash)
		})

		t.Run(fixtures[i].name+" invalid scripts cause problems for sighash (from checksig)", func(t *testing.T) {
			// Initalize public keys for tests
			publicKey, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
			_assert.NoError(t, err)

			signature, err := hex.DecodeString("30440220432deba8c65c2e1411282ffe4975ed9697b7833a169070df50b2b9f43408f4000220049b8774d71b3a72dc1abeccfb8f7f58398955baf2201db5249514e8ef7409da01")
			_assert.NoError(t, err)

			checker, err := creator(tx, txscript.NewTxSigHashes(tx), 0, value)
			_assert.NoError(t, err)

			validSig, err := checker.CheckSig(invalidScript, publicKey, signature, 0)
			_assert.Error(t, err)
			_assert.True(t, strings.Contains(err.Error(), "failed to parse script for sighash"))
			_assert.Nil(t, validSig)
		})
	}
}

func TestBitcoinCashCheckerRequiresSigHashEquals0(t *testing.T) {
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

	var value int64 = 12341234
	checker, err := BitcoinCashCheckerCreator(tx, txscript.NewTxSigHashes(tx), 0, value)
	_assert.NoError(t, err)

	hash, err := checker.GetSigHash([]byte(``), txscript.SigHashAll, 1)
	_assert.Error(t, err)
	_assert.EqualError(t, err, "Invalid sigVersion - must be 0 on bitcoin cash")
	_assert.Nil(t, hash)

	// Initalize public keys for tests
	publicKey, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
	_assert.NoError(t, err)

	signature, err := hex.DecodeString("30440220432deba8c65c2e1411282ffe4975ed9697b7833a169070df50b2b9f43408f4000220049b8774d71b3a72dc1abeccfb8f7f58398955baf2201db5249514e8ef7409da01")
	_assert.NoError(t, err)

	_, err = checker.CheckSig([]byte(``), publicKey, signature, 1)
	_assert.Error(t, err)
	_assert.EqualError(t, err, "checker failed to create sighash: Invalid sigVersion - must be 0 on bitcoin cash")
}

func TestCheckerCreator(t *testing.T) {
	fixtures := []struct {
		creator      CheckerCreator
		instanceType string
	}{
		{
			creator:      DummyBitcoinCheckerCreator,
			instanceType: btcDummy,
		},
		{
			creator:      BitcoinCheckerCreator,
			instanceType: btc,
		},
		{
			creator:      BitcoinCashCheckerCreator,
			instanceType: bch,
		},
	}

	for i := 0; i < len(fixtures); i++ {
		fixture := fixtures[i]
		creator := fixture.creator
		funcName := runtime.FuncForPC(reflect.ValueOf(creator).Pointer()).Name()

		t.Run(fmt.Sprintf("%s - checks input exists", funcName), func(t *testing.T) {
			tx := &wire.MsgTx{}
			sigHashes := txscript.NewTxSigHashes(tx)
			var value int64 = 12341234

			_, err := creator(tx, sigHashes, 0, value)
			_assert.Error(t, err)
			_assert.EqualError(t, err, "no input at this index")
		})

		t.Run(fmt.Sprintf("%s - nInput not negative", funcName), func(t *testing.T) {
			tx := &wire.MsgTx{}
			sigHashes := txscript.NewTxSigHashes(tx)
			var value int64 = 12341234

			_, err := creator(tx, sigHashes, -1, value)
			_assert.Error(t, err)
			_assert.EqualError(t, err, "no input at this index")
		})

		t.Run(fmt.Sprintf("%s - creates expected checker", funcName), func(t *testing.T) {
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

			sigHashes := txscript.NewTxSigHashes(tx)
			var value int64 = 12341234

			checker, err := creator(tx, sigHashes, 0, value)
			_assert.NoError(t, err)
			_assert.Implements(t, (*CheckerInterface)(nil), checker)

			switch fixture.instanceType {
			case btcDummy:
				_, ok := checker.(*dummyChecker)
				_assert.True(t, ok)
			case btc:
				_, ok := checker.(*bitcoinChecker)
				_assert.True(t, ok)
			case bch:
				_, ok := checker.(*bitcoinCashChecker)
				_assert.True(t, ok)
			default:
				t.Fail()
			}
		})

	}
}
