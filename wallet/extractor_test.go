package wallet

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btccom/btcsigner/bip32util"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/fastsha256"
	_assert "github.com/stretchr/testify/require"
	"strings"
	"testing"
)

// * Helper functions for converting scripts

// pubKeyHashAddrFromBytes produces a P2PKH address from a serialized pubKey
func pubKeyHashAddrFromBytes(t *testing.T, pubKey []byte, params *chaincfg.Params) *btcutil.AddressPubKeyHash {
	pubKeyHash := btcutil.Hash160(pubKey)
	pubKeyHashAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
	_assert.NoError(t, err)
	return pubKeyHashAddr
}

// pubKeyAddrFromBytes produces a P2PK address from a serialized pubKey
func pubKeyAddrFromBytes(t *testing.T, pubKey []byte, params *chaincfg.Params) *btcutil.AddressPubKey {
	pubKeyAddr, err := btcutil.NewAddressPubKey(pubKey, params)
	_assert.NoError(t, err)
	return pubKeyAddr
}

// addrToScript takes a generic address instance and
// produces it's scriptPubKey
func addrToScript(t *testing.T, addr btcutil.Address) []byte {
	script, err := txscript.PayToAddrScript(addr)
	_assert.NoError(t, err, "payToAddrScript should work for address")
	return script
}

// converts a redeemScript to a P2WSH address
func redeemScriptToAddress(t *testing.T, rs []byte, params *chaincfg.Params) *btcutil.AddressScriptHash {
	addr, err := btcutil.NewAddressScriptHash(rs, params)
	_assert.NoError(t, err, "should produce P2SH address for redeemScript")
	return addr
}

// converts a witnessScript to a P2WSH address
func witnessScriptToAddress(t *testing.T, ws []byte, params *chaincfg.Params) *btcutil.AddressWitnessScriptHash {
	scriptHash := fastsha256.Sum256(ws)
	addr, err := btcutil.NewAddressWitnessScriptHash(scriptHash[:], params)
	_assert.NoError(t, err, "should produce P2SH address for redeemScript")
	return addr
}

// Takes a redeemScript and produces the scriptPubKey
func toP2SHScript(t *testing.T, rs []byte, params *chaincfg.Params) []byte {
	return addrToScript(t, redeemScriptToAddress(t, rs, params))
}

// Takes a redeemScript and produces the witnessProgram
func toP2WSHScript(t *testing.T, ws []byte, params *chaincfg.Params) []byte {
	return addrToScript(t, witnessScriptToAddress(t, ws, params))
}

// * Helper functions to produce fixture data for various script forms

// spkFixture builds ScriptData structs for a bare scriptPubKey
func spkFixture(t *testing.T, script []byte, params *chaincfg.Params) (*ScriptData, *ScriptData, *ScriptData) {
	spkData := &ScriptData{}
	err := spkData.Parse(script, params)
	_assert.NoError(t, err)

	return spkData, nil, nil
}

// p2shFixture builds ScriptData structs for a redeemScript
func p2shFixture(t *testing.T, script []byte, params *chaincfg.Params) (*ScriptData, *ScriptData, *ScriptData) {
	p2shScript := toP2SHScript(t, script, params)

	spkData := &ScriptData{}
	err := spkData.Parse(p2shScript, params)
	_assert.NoError(t, err)

	rsData := &ScriptData{}
	err = rsData.Parse(script, params)
	_assert.NoError(t, err)

	return spkData, rsData, nil
}

// p2wshFixture builds ScriptData structs for a witnessScript
func p2wshFixture(t *testing.T, script []byte, params *chaincfg.Params) (*ScriptData, *ScriptData, *ScriptData) {
	p2wshScript := toP2WSHScript(t, script, params)

	spkData := &ScriptData{}
	err := spkData.Parse(p2wshScript, params)
	_assert.NoError(t, err)

	wsData := &ScriptData{}
	err = wsData.Parse(script, params)
	_assert.NoError(t, err)

	return spkData, nil, wsData
}

// p2shP2wshFixture builds ScriptData structs for a witnessScript nested
// in a witnessScript
func p2shP2wshFixture(t *testing.T, script []byte, params *chaincfg.Params) (*ScriptData, *ScriptData, *ScriptData) {
	wp := toP2WSHScript(t, script, params)
	p2shScript := toP2SHScript(t, wp, params)

	spkData := &ScriptData{}
	err := spkData.Parse(p2shScript, params)
	_assert.NoError(t, err)

	rsData := &ScriptData{}
	err = rsData.Parse(wp, params)
	_assert.NoError(t, err)

	wsData := &ScriptData{}
	err = wsData.Parse(script, params)
	_assert.NoError(t, err)

	return spkData, rsData, wsData
}

// * Helper functions to execute a test case for a certain script form

// verifySpk takes ScriptData structs, creates the FQS, and checks
// the appropriate features of a bare script
func verifySpk(t *testing.T, params *chaincfg.Params, spk *ScriptData, rs *ScriptData, ws *ScriptData) {
	fqs, err := newFullyQualifiedScript(params, spk, rs, ws)
	_assert.NoError(t, err)
	_assert.IsType(t, fullyQualifiedScript{}, *fqs)

	_assert.NotNil(t, fqs.spk)
	_assert.IsType(t, ScriptData{}, *fqs.spk)
	_assert.Equal(t, spk, fqs.spk)

	_assert.Nil(t, fqs.rs)
	_assert.Nil(t, fqs.ws)

	scriptSig := []byte{}
	witness := wire.TxWitness{}

	fqs2, err := fullyQualifiedScriptFromTxData(params, spk.Script, scriptSig, witness, nil, nil)
	_assert.NoError(t, err)
	_assert.Equal(t, fqs2.spk, spk)
	_assert.Nil(t, fqs2.rs)
	_assert.Nil(t, fqs2.ws)
}

// verifyP2sh takes ScriptData structs, creates the FQS, and checks
// the appropriate features of a P2SH script
func verifyP2sh(t *testing.T, params *chaincfg.Params, spk *ScriptData, rs *ScriptData, ws *ScriptData) {
	fqs, err := newFullyQualifiedScript(params, spk, rs, ws)
	_assert.NoError(t, err)
	_assert.IsType(t, fullyQualifiedScript{}, *fqs)

	_assert.NotNil(t, fqs.spk)
	_assert.IsType(t, ScriptData{}, *fqs.spk)
	_assert.Equal(t, spk, fqs.spk)

	_assert.NotNil(t, fqs.spk)
	_assert.IsType(t, ScriptData{}, *fqs.rs)
	_assert.Equal(t, rs, fqs.rs)

	_assert.Nil(t, fqs.ws)

	scriptSig := []byte{}
	witness := wire.TxWitness{}

	fqs2, err := fullyQualifiedScriptFromTxData(params, spk.Script, scriptSig, witness, rs.Script, nil)
	_assert.NoError(t, err)
	_assert.Equal(t, spk, fqs2.spk)
	_assert.Equal(t, rs, fqs2.rs)
	_assert.Nil(t, fqs2.ws)
}

// verifyP2wsh takes ScriptData structs, creates the FQS, and checks
// the appropriate features of a P2WSH script
func verifyP2wsh(t *testing.T, params *chaincfg.Params, spk *ScriptData, rs *ScriptData, ws *ScriptData) {
	fqs, err := newFullyQualifiedScript(params, spk, rs, ws)
	_assert.NoError(t, err)
	_assert.IsType(t, fullyQualifiedScript{}, *fqs)

	_assert.NotNil(t, fqs.spk)
	_assert.IsType(t, ScriptData{}, *fqs.spk)
	_assert.Equal(t, spk, fqs.spk)

	_assert.NotNil(t, fqs.ws)
	_assert.IsType(t, ScriptData{}, *fqs.ws)
	_assert.Equal(t, ws, fqs.ws)

	_assert.Nil(t, fqs.rs)

	scriptSig := []byte{}
	witness := wire.TxWitness{}

	fqs2, err := fullyQualifiedScriptFromTxData(params, spk.Script, scriptSig, witness, nil, ws.Script)
	_assert.NoError(t, err)
	_assert.Equal(t, spk, fqs2.spk)
	_assert.Equal(t, ws, fqs2.ws)
	_assert.Nil(t, fqs2.rs)
}

// verifyP2wsh takes ScriptData structs, creates the FQS, and checks
// the appropriate features of a P2WSH script
func verifyP2shP2wsh(t *testing.T, params *chaincfg.Params, spk *ScriptData, rs *ScriptData, ws *ScriptData) {
	fqs, err := newFullyQualifiedScript(params, spk, rs, ws)
	_assert.NoError(t, err)
	_assert.IsType(t, fullyQualifiedScript{}, *fqs)

	_assert.NotNil(t, fqs.spk)
	_assert.IsType(t, ScriptData{}, *fqs.spk)
	_assert.Equal(t, spk, fqs.spk)

	_assert.NotNil(t, fqs.rs)
	_assert.IsType(t, ScriptData{}, *fqs.rs)
	_assert.Equal(t, rs, fqs.rs)

	_assert.NotNil(t, fqs.ws)
	_assert.IsType(t, ScriptData{}, *fqs.ws)
	_assert.Equal(t, ws, fqs.ws)

	scriptSig := []byte{}
	witness := wire.TxWitness{}

	fqs2, err := fullyQualifiedScriptFromTxData(params, spk.Script, scriptSig, witness, rs.Script, ws.Script)
	_assert.NoError(t, err)
	_assert.Equal(t, spk, fqs2.spk)
	_assert.Equal(t, rs, fqs2.rs)
	_assert.Equal(t, ws, fqs2.ws)
}

func TestExtractor(t *testing.T) {
	params := &chaincfg.TestNet3Params

	// Initalize public keys for tests
	pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
	_assert.NoError(t, err)

	pubKey2, err := hex.DecodeString("030b61aecceafa61eaeff5b3ed38943a462e63a7c2ca8cb43f4726e787c759ef53")
	_assert.NoError(t, err)

	multisig1Key := make([]*btcutil.AddressPubKey, 1)
	multisig1Key[0] = pubKeyAddrFromBytes(t, pubKey1, params)

	multisig2Keys := make([]*btcutil.AddressPubKey, 2)
	multisig2Keys[0] = pubKeyAddrFromBytes(t, pubKey1, params)
	multisig2Keys[1] = pubKeyAddrFromBytes(t, pubKey2, params)

	// create scripts

	pubKeyHashScript := addrToScript(t, pubKeyHashAddrFromBytes(t, pubKey1, params))

	pubKeyScript := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))

	multisigScript1of1, err := txscript.MultiSigScript(multisig1Key, 1)
	multisigScript1of2, err := txscript.MultiSigScript(multisig2Keys, 1)
	multisigScript2of2, err := txscript.MultiSigScript(multisig2Keys, 2)

	scripts := make([][]byte, 5)
	scripts[0] = pubKeyHashScript
	scripts[1] = pubKeyScript
	scripts[2] = multisigScript1of1
	scripts[3] = multisigScript1of2
	scripts[4] = multisigScript2of2

	for _, script := range scripts {
		t.Run("test as base spk", func(t *testing.T) {
			spk, rs, ws := spkFixture(t, script, params)
			verifySpk(t, params, spk, rs, ws)
		})

		t.Run("test as p2sh spk", func(t *testing.T) {
			spk, rs, ws := p2shFixture(t, script, params)
			verifyP2sh(t, params, spk, rs, ws)
		})
		t.Run("test as p2wsh spk", func(t *testing.T) {
			spk, rs, ws := p2wshFixture(t, script, params)
			verifyP2wsh(t, params, spk, rs, ws)
		})
		t.Run("test as p2sh|p2wsh spk", func(t *testing.T) {
			spk, rs, ws := p2shP2wshFixture(t, script, params)
			verifyP2shP2wsh(t, params, spk, rs, ws)
		})
	}
}

func TestFullyQualifiedScriptFailure(t *testing.T) {
	params := &chaincfg.TestNet3Params
	t.Run("p2sh script requires redeemScript", func(t *testing.T) {
		var script []byte
		p2shScript := addrToScript(t, redeemScriptToAddress(t, script, params))
		p2shData := &ScriptData{}
		err := p2shData.Parse(p2shScript, params)
		_assert.NoError(t, err)
		fqs, err := newFullyQualifiedScript(params, p2shData, nil, nil)
		_assert.Error(t, err)
		_assert.Nil(t, fqs)
		_assert.EqualError(t, err, "missing redeemScript")
	})

	t.Run("redeemScript must match P2SH script", func(t *testing.T) {
		var script []byte
		p2shScript := addrToScript(t, redeemScriptToAddress(t, script, params))
		p2shData := &ScriptData{}

		err := p2shData.Parse(p2shScript, params)
		_assert.NoError(t, err)

		pubKey, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)
		pubKeyHashScript := addrToScript(t, pubKeyHashAddrFromBytes(t, pubKey, params))

		otherScript := &ScriptData{}
		err = otherScript.Parse(pubKeyHashScript, params)
		_assert.NoError(t, err)

		fqs, err := newFullyQualifiedScript(params, p2shData, otherScript, nil)
		_assert.Error(t, err)
		_assert.Nil(t, fqs)
		_assert.EqualError(t, err, "redeemScript doesn't satisfy pay-to-script-hash")
	})

	t.Run("unrequested redeemScript", func(t *testing.T) {
		pubKey, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		pubKeyHashScript := addrToScript(t, pubKeyHashAddrFromBytes(t, pubKey, params))

		otherScript := &ScriptData{}
		err = otherScript.Parse(pubKeyHashScript, params)
		_assert.NoError(t, err)

		fqs, err := newFullyQualifiedScript(params, otherScript, otherScript, nil)
		_assert.Error(t, err)
		_assert.Nil(t, fqs)
		_assert.EqualError(t, err, "superfluous redeemScript")
	})

	t.Run("unrequested witnessScript", func(t *testing.T) {
		pubKey, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		pubKeyHashScript := addrToScript(t, pubKeyHashAddrFromBytes(t, pubKey, params))

		otherScript := &ScriptData{}
		err = otherScript.Parse(pubKeyHashScript, params)
		_assert.NoError(t, err)

		fqs, err := newFullyQualifiedScript(params, otherScript, nil, otherScript)
		_assert.Error(t, err)
		_assert.Nil(t, fqs)
		_assert.EqualError(t, err, "superfluous witnessScript")
	})

	t.Run("p2wsh script requires witnessScript", func(t *testing.T) {
		var script []byte
		p2wshScript := addrToScript(t, witnessScriptToAddress(t, script, params))
		p2wshData := &ScriptData{}
		err := p2wshData.Parse(p2wshScript, params)
		_assert.NoError(t, err)
		fqs, err := newFullyQualifiedScript(params, p2wshData, nil, nil)
		_assert.Error(t, err)
		_assert.Nil(t, fqs)
		_assert.EqualError(t, err, "missing witnessScript")
	})

	t.Run("nested p2sh p2wsh script requires witnessScript", func(t *testing.T) {
		var script []byte
		witnessProgram := addrToScript(t, witnessScriptToAddress(t, script, params))
		p2wshData := &ScriptData{}
		err := p2wshData.Parse(witnessProgram, params)
		_assert.NoError(t, err)

		p2shScript := addrToScript(t, redeemScriptToAddress(t, witnessProgram, params))
		p2shData := &ScriptData{}
		err = p2shData.Parse(p2shScript, params)
		_assert.NoError(t, err)

		fqs, err := newFullyQualifiedScript(params, p2shData, p2wshData, nil)
		_assert.Error(t, err)
		_assert.Nil(t, fqs)
		_assert.EqualError(t, err, "missing witnessScript")
	})
}

func TestStackExtraction(t *testing.T) {
	params := &chaincfg.TestNet3Params

	sigHashKeyHashSpk, err := hex.DecodeString("76a9140de1f9b92d2ab6d8ead83f9a0ff5cf518dcb03b888ac")
	_assert.NoError(t, err)

	p2pkSpk, err := hex.DecodeString("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac")
	_assert.NoError(t, err)

	p2wpkhSpk, err := hex.DecodeString("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
	_assert.NoError(t, err)

	p2wpkhSpk2, err := hex.DecodeString("001479091972186c449eb1ded22b78e40d009bdf0089")
	_assert.NoError(t, err)

	p2shP2wpkhSpk2, err := hex.DecodeString("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387")
	_assert.NoError(t, err)

	sixOfSix, err := hex.DecodeString("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae")
	_assert.NoError(t, err)

	sixOfSixWP, err := hex.DecodeString("0020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54")
	_assert.NoError(t, err)

	sixOfSixWPSPK, err := hex.DecodeString("a9149993a429037b5d912407a71c252019287b8d27a587")
	_assert.NoError(t, err)

	p2pkSpk1, err := hex.DecodeString("21038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2bac")
	_assert.NoError(t, err)

	p2shP2pkSpk1, err := hex.DecodeString("a914c99d9ebb5a4828e4e1b606dd6a51a2babebbdc0987")
	_assert.NoError(t, err)

	p2wshP2pkSpk1, err := hex.DecodeString("00200f9ea7bae7166c980169059e39443ed13324495b0d6678ce716262e879591210")
	_assert.NoError(t, err)

	p2shP2wshP2pkSpk1, err := hex.DecodeString("a9146d185c7042d01ea8276dc6be6603101dc441d8a487")
	_assert.NoError(t, err)

	p2pkhSpk1, err := hex.DecodeString("76a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac")
	_assert.NoError(t, err)

	p2shP2pkhSpk1, err := hex.DecodeString("a9142162ff7c23d47a0c331f95c67d7c3e22abb12a0287")
	_assert.NoError(t, err)

	p2wshP2pkhSpk1, err := hex.DecodeString("0020578db4b54a6961060b71385c17d3280379a557224c52b11b19a3a1c1eef606a0")
	_assert.NoError(t, err)

	p2shP2wshP2pkhSpk1, err := hex.DecodeString("a91444a641c4e06eb6118c99e5ed29954b705b50fb6a87")
	_assert.NoError(t, err)

	multisigSpk1, err := hex.DecodeString("5121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b51ae")
	_assert.NoError(t, err)

	p2shMultisigSpk1, err := hex.DecodeString("a91438c064c6387d1071eeb5c3d90350054aea0b3fc187")
	_assert.NoError(t, err)

	p2wshMultisigSpk1, err := hex.DecodeString("00201b8c0c2878c5634c3ce738cdc568c592e99783dbd28ff4c6cb5b7b4675d9ee99")
	_assert.NoError(t, err)

	p2shP2wshMultisigSpk1, err := hex.DecodeString("a914cc6ea17c33de7996471e40892acdd6e5f61b9b6f87")
	_assert.NoError(t, err)

	p2wpkhSpk3, err := hex.DecodeString("0014851a33a5ef0d4279bd5854949174e2c65b1d4500")
	_assert.NoError(t, err)

	p2shP2wpkhSpk3, err := hex.DecodeString("a9140d061ae2c8ad224a81142a2e02181f5173b576b387")
	_assert.NoError(t, err)

	type inputFixtureRow []struct {
		nIn           int
		scriptType    txscript.ScriptClass
		value         int64
		segwit        bool
		scriptPubKey  []byte
		redeemScript  []byte
		witnessScript []byte
		expected      [][]byte
	}

	fixtures := []struct {
		tx      string
		checker CheckerCreator
		inputs  inputFixtureRow
	}{
		{
			tx: "01000000012ffb29d53528ad30c37c267fbbeda3c6fce08f5f6f5d3b1eab22193599a3612a010000006b483045022100dad4bd28448e626ecb1ade42a09c43559d50b61b57a06fac992a5ecdd73deb740220524082f83560e2df9afaa283c699dec4c5b01687484d73e7b280e5a506caf1c4032102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff02c0e1e400000000001976a9140de1f9b92d2ab6d8ead83f9a0ff5cf518dcb03b888ac80969800000000001976a91454d0e925d5ee0ee26768a237067dee793d01a70688ac00000000",
			inputs: inputFixtureRow{
				{
					scriptType:   txscript.PubKeyHashTy,
					nIn:          0,
					value:        30000000,
					scriptPubKey: sigHashKeyHashSpk,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000037db7f0b2a345ded6ddf28da3211a7d7a95a2943e9a879493d6481b7d69613f04010000006a47304402206abb0622b8b6ca83f1f4de84830cf38bf4615dc9e47a7dcdcc489905f26aa9cb02201d2d8a7815242b88e4cd66390ca46da802238f9b1395e0d118213d30dad38184012102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff652c491e5a781a6a3c547fa8d980741acbe4623ae52907278f10e1f064f67e05000000006b483045022100de13b42804f87a09bb46def12ab4608108d8c2db41db4bc09064f9c46fcf493102205e5c759ab7b2895c9b0447e56029f6895ff7bb20e0847c564a88a3cfcf080c4f012102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffffb9fa270fa3e4dd8c79f9cbfe5f1953cba071ed081f7c277a49c33466c695db35000000006b4830450221009100a3f5b30182d1cb0172792af6947b6d8d42badb0539f2c209aece5a0628f002200ae91702ca63347e344c85fcb536f30ee97b75cdf4900de534ed5e040e71a548012102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff03204e0000000000001976a9149ed1f577c60e4be1dbf35318ec12f51d25e8577388ac30750000000000001976a914fb407e88c48921d5547d899e18a7c0a36919f54d88ac50c30000000000001976a91404ccb4eed8cfa9f6e394e945178960f5ccddb38788ac00000000",
			inputs: inputFixtureRow{
				{
					scriptType:   txscript.PubKeyHashTy,
					nIn:          0,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
				},
				{
					scriptType:   txscript.PubKeyHashTy,
					nIn:          1,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
				},
				{
					scriptType:   txscript.PubKeyHashTy,
					nIn:          2,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000037db7f0b2a345ded6ddf28da3211a7d7a95a2943e9a879493d6481b7d69613f04010000006b483045022100bd2829550e9b3a081747281029b5f5a96bbd83bb6a92fa2f8310f1bd0d53abc90220071b469417c55cdb3b04171fd7900d2768981b7ab011553d84d24ea85d277079812102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff652c491e5a781a6a3c547fa8d980741acbe4623ae52907278f10e1f064f67e05000000006a47304402206295e17c45c6356ffb20365b696bcbb869db7e8697f4b8a684098ee2bff85feb02202905c441abe39ec9c480749236b84fdd3ebd91ecd25b559136370aacfcf2815c812102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffffb9fa270fa3e4dd8c79f9cbfe5f1953cba071ed081f7c277a49c33466c695db35000000006b483045022100f58e7c98ac8412944d575bcdece0e5966d4018f05988b5b60b6f46b8cb7a543102201c5854d3361e29b58123f34218cec2c722f5ec7a08235ebd007ec637b07c193a812102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff03204e0000000000001976a9149ed1f577c60e4be1dbf35318ec12f51d25e8577388ac30750000000000001976a914fb407e88c48921d5547d899e18a7c0a36919f54d88ac50c30000000000001976a91404ccb4eed8cfa9f6e394e945178960f5ccddb38788ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          1,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          2,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000037db7f0b2a345ded6ddf28da3211a7d7a95a2943e9a879493d6481b7d69613f04010000006b483045022100e822f152bb15a1d623b91913cd0fb915e9f85a8dc6c26d51948208bbc0218e800220255f78549d9614c88eac9551429bc00224f22cdcb41a3af70d52138f7e98d333032102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff652c491e5a781a6a3c547fa8d980741acbe4623ae52907278f10e1f064f67e05000000006a47304402206f37f79adeb86e0e2da679f79ff5c3ba206c6d35cd9a21433f0de34ee83ddbc00220118cabbac5d83b3aa4c2dc01b061e4b2fe83750d85a72ae6a1752300ee5d9aff032102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffffb9fa270fa3e4dd8c79f9cbfe5f1953cba071ed081f7c277a49c33466c695db35000000006a473044022019a2a3322dcdb0e0c25df9f03f264f2c88f43b3b648fec7a28cb85620393a9750220135ff3a6668c6d6c05f32069e47a1feda10979935af2470c97fcb388f96f9738032102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff02204e0000000000001976a9149ed1f577c60e4be1dbf35318ec12f51d25e8577388ac30750000000000001976a914fb407e88c48921d5547d899e18a7c0a36919f54d88ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          1,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          2,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000037db7f0b2a345ded6ddf28da3211a7d7a95a2943e9a879493d6481b7d69613f04010000006b483045022100d05a3b6cf2f0301000b0e45c09054f2c61570ce8798ebf571eef72da3b1c94a1022016d7ef3c133fa703bae2c75158ea08d335ac698506f99b3c369c37a9e8fc4beb832102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff652c491e5a781a6a3c547fa8d980741acbe4623ae52907278f10e1f064f67e05000000006b483045022100ee6bf07b051001dcbfa062692a40adddd070303286b714825b3fb4693dd8fcdb022056610885e5053e5d47f2be3433051305abe7978ead8f7cf2d0368947aff6b307832102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffffb9fa270fa3e4dd8c79f9cbfe5f1953cba071ed081f7c277a49c33466c695db35000000006b483045022100cfc930d5b5272d0220d9da98fabec97b9e66306f735efa837f43f6adc675cad902202f9dff76b8b9ec8f613d46094f17f64d875804292d8804aa59fd295b6fc1416b832102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff03204e0000000000001976a9149ed1f577c60e4be1dbf35318ec12f51d25e8577388ac30750000000000001976a914fb407e88c48921d5547d899e18a7c0a36919f54d88ac50c30000000000001976a91404ccb4eed8cfa9f6e394e945178960f5ccddb38788ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          1,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          2,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000037db7f0b2a345ded6ddf28da3211a7d7a95a2943e9a879493d6481b7d69613f04010000006b483045022100e7f0a1ddd2c0b81e093e029b8a503afa27fe43549b0668d2141abf35eb3a63be022037f12d12cd50fc94a135f933406a8937557de9b9566a8841ff1548c1b6984531022102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff652c491e5a781a6a3c547fa8d980741acbe4623ae52907278f10e1f064f67e05000000006a473044022008451123ec2535dab545ade9d697519e63b28df5e311ea05e0ce28d39877a7c8022061ce5dbfb7ab478dd9e05b0acfd959ac3eb2641f61958f5d352f37621073d7c0022102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffffb9fa270fa3e4dd8c79f9cbfe5f1953cba071ed081f7c277a49c33466c695db35000000006a47304402205c001bcdfb35c70d8aa3bdbc75399afb72eb7cf1926ca7c1dfcddcb4d4d3e0f8022028992fffdcd4e9f34ab726f97c24157917641c2ef99361f588e3d4147d46eea5022102f1c7eac9200f8dee7e34e59318ff2076c8b3e3ac7f43121e57569a1aec1803d4ffffffff03204e0000000000001976a9149ed1f577c60e4be1dbf35318ec12f51d25e8577388ac30750000000000001976a914fb407e88c48921d5547d899e18a7c0a36919f54d88ac50c30000000000001976a91404ccb4eed8cfa9f6e394e945178960f5ccddb38788ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          1,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
				{
					nIn:          2,
					value:        40000,
					scriptPubKey: sigHashKeyHashSpk,
					scriptType:   txscript.PubKeyHashTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        625000000,
					scriptPubKey: p2pkSpk,
					scriptType:   txscript.PubKeyTy,
				},
				{
					nIn:          1,
					value:        600000000,
					scriptPubKey: p2wpkhSpk,
					scriptType:   txscript.WitnessV0PubKeyHashTy,
					segwit:       true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        1000000000,
					scriptPubKey: p2shP2wpkhSpk2,
					redeemScript: p2wpkhSpk2,
					scriptType:   txscript.WitnessV0PubKeyHashTy,
					segwit:       true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000",
			inputs: inputFixtureRow{
				{
					nIn:           0,
					value:         987654321,
					scriptPubKey:  sixOfSixWPSPK,
					redeemScript:  sixOfSixWP,
					witnessScript: sixOfSix,
					scriptType:    txscript.MultiSigTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "010000000193aef40ae141694895e99e18e49d0181b086dd7c011c0241175c6eaf320099970000000049483045022100e57eba5380dcc8a7bdb5370b423dadd43070e1ca268f94bc97b2ded55ca45e9502206a43151c8af03a00f0ac86526d07981e303fc0daea8c6ed435abe8961533046d01ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        80000,
					scriptPubKey: p2pkSpk1,
					scriptType:   txscript.PubKeyTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "0100000001a30e865fa60f6c25a8b218bb5a6b9acc7cf3f1db2f2e3a7114b51af5d6ae811f000000006c473044022026d2b56b6cb0269bf4e80dd655b9e917019e2ccef57f4b858d03bb45a2da59d9022010519a7f327f03e7c9613e0694f929544af29d3682e7ec8f19147e7a86651ecd012321038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2bacffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        80000,
					scriptPubKey: p2shP2pkSpk1,
					redeemScript: p2pkSpk1,
					scriptType:   txscript.PubKeyTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "010000000001014533a3bc1e039bd787656068e135aaee10aee95a64776bfc047ee6a7c1ebdd2f0000000000ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac02473044022039725bb7291a14dd182dafdeaf3ea0d5c05c34f4617ccbaa46522ca913995c4e02203b170d072ed2e489e7424ad96d8fa888deb530be2d4c5d9aaddf111a7efdb2d3012321038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2bac00000000",
			inputs: inputFixtureRow{
				{
					nIn:           0,
					value:         80000,
					scriptPubKey:  p2wshP2pkSpk1,
					witnessScript: p2pkSpk1,
					scriptType:    txscript.PubKeyTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000000101e0779d448aaa203a96b3de14d0482e26dd75a4278ae5bb6d7cc18e6874f3866000000000232200200f9ea7bae7166c980169059e39443ed13324495b0d6678ce716262e879591210ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac024730440220014207a5f0601ed7b3c3f9d82309b32e8f76dd6776a55cb5f8684b9ff029e0850220693afd7b69471b51d9354cc1a956b68b8d48e32f6b0ad7a19bb5dd3e4499179a012321038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2bac00000000",
			inputs: inputFixtureRow{
				{
					nIn:           0,
					value:         80000,
					scriptPubKey:  p2shP2wshP2pkSpk1,
					redeemScript:  p2wshP2pkSpk1,
					witnessScript: p2pkSpk1,
					scriptType:    txscript.PubKeyTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "010000000193aef40ae141694895e99e18e49d0181b086dd7c011c0241175c6eaf320099970000000049483045022100e57eba5380dcc8a7bdb5370b423dadd43070e1ca268f94bc97b2ded55ca45e9502206a43151c8af03a00f0ac86526d07981e303fc0daea8c6ed435abe8961533046d01ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        80000,
					scriptPubKey: p2pkhSpk1,
					scriptType:   txscript.PubKeyHashTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000014b9ffc17c3cce03ee66980bf32d36aaa13462980c3af9d9d29ec6b97ab1c91650000000084473044022003d738d855d0c54a419ac62ebe1a1c0bf2dc6993c9585adb9a8666736658107002204d57ff62ee7efae6df73430bba62494faeba8c125a4abcf2488757a4f8877dd50121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b1976a914851a33a5ef0d4279bd5854949174e2c65b1d450088acffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:          0,
					value:        80000,
					scriptPubKey: p2shP2pkhSpk1,
					redeemScript: p2pkhSpk1,
					scriptType:   txscript.PubKeyHashTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "0100000000010123539877e39a273819006de1c433e09f9e9af201fc178dd0f2cf2eaa5ad53b480000000000ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac03483045022100f02a82b0a94a5d5dc4d2127ac34be62cb066713d71d56bdf5ef7810ab57a157302205f24abdde1dab554a02edcf378e98828024e57272e5e474a5b04accdca080a030121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b1976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:           0,
					value:         80000,
					scriptPubKey:  p2wshP2pkhSpk1,
					witnessScript: p2pkhSpk1,
					scriptType:    txscript.PubKeyHashTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000000101363dfbfe2566db77e3b1195bedf1d0daeb9ce526cd7611ba81759b2654ce415c0000000023220020578db4b54a6961060b71385c17d3280379a557224c52b11b19a3a1c1eef606a0ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac03483045022100c8bd5ebb26ba6719158650c3e7c5e80be4c886ba025c44cc41f5149b3114705a02203ac6e1f38f6c081d506f28f1b5e38ebec9e0f0fa911d0e3f68d48d8b0e77b34b0121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b1976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:           0,
					value:         80000,
					scriptPubKey:  p2shP2wshP2pkhSpk1,
					redeemScript:  p2wshP2pkhSpk1,
					witnessScript: p2pkhSpk1,
					scriptType:    txscript.PubKeyHashTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},

		{
			tx: "010000000179310ec46e734b3490ee839c5ae4a09d28561ee9fff2d051f733d201f958d6d2000000004a00483045022100d269531f120f377ed2f94f42bef893ff2fe6544ac97fb477fa291bc6cfb7647e02200983f6a5bbd4ce6cf97f571995634805a7324cc5d8353ed954fa62477b0fcd0901ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:   0,
					value: 80000,

					scriptPubKey: multisigSpk1,
					scriptType:   txscript.MultiSigTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "010000000152882c661c49dd2f53bd9ced7e9f44b184888ad2fe7d86737f0efaa7aecdced1000000006f00473044022025f2e161f0a97888df948f4dcc7c04fe502510b8d8260ca9920f38d55e4d17720220271b6843224b3a34542a4df31781d048da56ee46b8c5fb99043e30abd527b2d801255121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b51aeffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac00000000",
			inputs: inputFixtureRow{
				{
					nIn:   0,
					value: 80000,

					scriptPubKey: p2shMultisigSpk1,
					redeemScript: multisigSpk1,
					scriptType:   txscript.MultiSigTy,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "01000000000101c1eced6216de0889d4629ff64a8af8e8ec6d0b414de0c57b46c02cc303d321fe0000000000ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac0300483045022100d4c0cbdb45915b8a3162362fa5f74556de919aeda5337fc44a7fb000e833460d022017742c37d7a061e2ae3a086c7c585c9c85e5d31af468d3e00045c0f35b8f8eb601255121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b51ae00000000",
			inputs: inputFixtureRow{
				{
					nIn:   0,
					value: 80000,

					scriptPubKey:  p2wshMultisigSpk1,
					witnessScript: multisigSpk1,
					scriptType:    txscript.MultiSigTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "010000000001013a5a2ab0223d3b504b52af76d650329750666fbf1be13d4cb08d0d9fc550a47d00000000232200201b8c0c2878c5634c3ce738cdc568c592e99783dbd28ff4c6cb5b7b4675d9ee99ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac0300483045022100c97a5e205ce0023d3d44f846abf1f0e21b6f2646bd2496bbe92e4333fe4401be02201247e047d669f713582713e35d2eba430abc3d75a924bb500362bf47d6234ed501255121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b51ae00000000",
			inputs: inputFixtureRow{
				{
					nIn:   0,
					value: 80000,

					scriptPubKey:  p2shP2wshMultisigSpk1,
					redeemScript:  p2wshMultisigSpk1,
					witnessScript: multisigSpk1,
					scriptType:    txscript.MultiSigTy,
					segwit:        true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "0100000000010133defbe3e28860007ff3e21222774c220cb35d554fa3e3796d25bf8ee983e1080000000000ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac0248304502210097c3006f0b390982eb47f762b2853773c6cedf83668a22d710f4c13c4fd6b15502205e26ef16a81fc818a37f3a34fc6d0700e61100ea6c6773907c9c046042c440340121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b00000000",
			inputs: inputFixtureRow{
				{
					nIn:   0,
					value: 80000,

					scriptPubKey: p2wpkhSpk3,
					scriptType:   txscript.WitnessV0PubKeyHashTy,
					segwit:       true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
		{
			tx: "010000000001015df9a0b9ade2d835881704e0f53b51a4b19ecfc794ea1f3555783dd7f68659ce0000000017160014851a33a5ef0d4279bd5854949174e2c65b1d4500ffffffff0160ea0000000000001976a914851a33a5ef0d4279bd5854949174e2c65b1d450088ac02483045022100cb3929c128fec5108071b662e5af58e39ac8708882753a421455ca80462956f6022030c0f4738dd1a13fc7a34393002d25c6e8a6399f29c7db4b98f53a9475d94ca20121038de63cf582d058a399a176825c045672d5ff8ea25b64d28d4375dcdb14c02b2b00000000",
			inputs: inputFixtureRow{
				{
					nIn:   0,
					value: 80000,

					scriptPubKey: p2shP2wpkhSpk3,
					redeemScript: p2wpkhSpk3,
					scriptType:   txscript.WitnessV0PubKeyHashTy,
					segwit:       true,
				},
			},
			checker: BitcoinCheckerCreator,
		},
	}

	for i := 0; i < len(fixtures); i++ {
		t.Run("extract stack, and sig/keys", func(t *testing.T) {
			fixture := fixtures[i]
			txBytes, err := hex.DecodeString(fixture.tx)
			_assert.NoError(t, err)

			utilTx, err := btcutil.NewTxFromBytes(txBytes)
			_assert.NoError(t, err)

			tx := utilTx.MsgTx()
			for _, inputV := range fixture.inputs {
				_assert.True(t, inputV.nIn >= 0 && inputV.nIn <= len(tx.TxIn))

				scriptSig := tx.TxIn[inputV.nIn].SignatureScript
				witness := tx.TxIn[inputV.nIn].Witness

				extractStack, fqs, err := extractScriptAndSigChunks(params,
					inputV.scriptPubKey, scriptSig, witness, inputV.redeemScript, inputV.witnessScript)

				_assert.NoError(t, err)
				_assert.NotNil(t, fqs)
				_assert.Equal(t, inputV.segwit, fqs.isSegwit())

				encodeSig, encodeWitness, err := fqs.encodeStack(extractStack)
				_assert.True(t, bytes.Equal(scriptSig, encodeSig))
				_assert.Equal(t, len(witness), len(encodeWitness))

				checker, err := fixture.checker(tx, txscript.NewTxSigHashes(tx), inputV.nIn, inputV.value)
				_assert.NoError(t, err)

				reader := NewScriptReader(StrictMultisigFrameReader)
				_assert.NoError(t, err)

				_, _, err = extractSigsFromChunks(reader, fqs.sign, extractStack, checker, fqs.sigVersion)
				_assert.NoError(t, err)
			}
		})
	}
}

func TestRemoveLast(t *testing.T) {
	t.Run("empty list returns empty", func(t *testing.T) {
		input := [][]byte{}
		input2 := removeLast(input)
		_assert.Equal(t, 0, len(input2))
	})

	t.Run("removes only element", func(t *testing.T) {
		input := [][]byte{
			{0x01},
		}
		input2 := removeLast(input)
		_assert.Equal(t, 0, len(input2))
	})

	t.Run("removes only last", func(t *testing.T) {
		input := [][]byte{
			{0x02},
			{0x01},
			{0x00},
		}

		input2 := removeLast(input)
		_assert.Equal(t, 2, len(input2))
		_assert.True(t, bytes.Equal(input[0], input2[0]))
		_assert.True(t, bytes.Equal(input[1], input2[1]))
	})
}

func TestFindScriptAndCheck(t *testing.T) {
	t.Run("returns error if no script found", func(t *testing.T) {
		var list [][]byte
		var known []byte

		ret, err := findScriptAndCheck(list, known)

		_assert.Error(t, err)
		_assert.EqualError(t, err, "no committed script was provided, and scriptData was empty")
		_assert.Nil(t, ret)
	})

	t.Run("returns committed script if list empty", func(t *testing.T) {
		var list [][]byte
		known := []byte{0x00}

		ret, err := findScriptAndCheck(list, known)

		_assert.NoError(t, err)
		_assert.True(t, bytes.Equal(ret, known))
	})

	t.Run("returns 0th element script if no committed script given", func(t *testing.T) {
		list := [][]byte{
			{0x00},
		}

		var known []byte

		ret, err := findScriptAndCheck(list, known)

		_assert.NoError(t, err)
		_assert.True(t, bytes.Equal(ret, list[len(list)-1]))
	})

	t.Run("returns last element script if no committed script given", func(t *testing.T) {
		list := [][]byte{
			{0x02},
			{0x01},
			{0x00},
		}

		var known []byte

		ret, err := findScriptAndCheck(list, known)

		_assert.NoError(t, err)
		_assert.True(t, bytes.Equal(ret, list[len(list)-1]))
	})

	t.Run("returns last element if it matches", func(t *testing.T) {
		list := [][]byte{
			{0x02},
			{0x01},
			{0x00},
		}

		known := []byte{0x00}

		ret, err := findScriptAndCheck(list, known)

		_assert.NoError(t, err)
		_assert.True(t, bytes.Equal(ret, list[len(list)-1]))
	})

	t.Run("errors if element doesnt match", func(t *testing.T) {
		list := [][]byte{
			{0x02},
			{0x01},
			{0x00},
		}

		known := []byte{0x01}

		ret, err := findScriptAndCheck(list, known)

		_assert.Error(t, err)
		_assert.Nil(t, ret)
		_assert.EqualError(t, err, "last element of chunks didn't match provided script")
	})
}

func TestExtractSigsFromChunks(t *testing.T) {

	t.Run("rejects invalid types", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		p2wpkh, err := hex.DecodeString("0014851a33a5ef0d4279bd5854949174e2c65b1d4500")
		_assert.NoError(t, err)

		scriptData := &ScriptData{}
		err = scriptData.Parse(p2wpkh, params)
		_assert.NoError(t, err)

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

		checker, err := DummyBitcoinCheckerCreator(tx, txscript.NewTxSigHashes(tx), 0, 0)
		_assert.NoError(t, err)

		reader := NewScriptReader(StrictMultisigFrameReader)
		sigs, keys, err := extractSigsFromChunks(reader, scriptData, [][]byte{}, checker, 0)
		_assert.Error(t, err)
		_assert.EqualError(t, err, "unsupported script")
		_assert.Nil(t, sigs)
		_assert.Nil(t, keys)
	})

}

func TestFullyQualifiedScriptFromTxData(t *testing.T) {
	t.Run("test requires valid scriptPubKey", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		script := []byte{0x01}
		fqs, err := fullyQualifiedScriptFromTxData(params, script, nil, nil, nil, nil)
		_assert.Error(t, err)
		_assert.True(t, strings.Contains(err.Error(), "invalid scriptPubKey"))
		_assert.Nil(t, fqs)
	})

	// tests that the operation fails because the
	// scriptSig is not a valid script.
	t.Run("test P2SH and invalid scriptSig", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		// Initalize public keys for tests
		pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		p2pkRedeemScript := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))
		p2shScript := addrToScript(t, redeemScriptToAddress(t, p2pkRedeemScript, params))
		scriptSig := []byte{0x01}

		fqs, err := fullyQualifiedScriptFromTxData(params,
			p2shScript, scriptSig, nil, nil, nil)

		_assert.Error(t, err)
		_assert.True(t, strings.Contains(err.Error(), "invalid scriptSig"))
		_assert.Nil(t, fqs)
	})

	// tests that the operation fails because the
	// scriptSig is not a valid script.
	t.Run("test P2WSH and invalid witnessScript", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		// Initalize public keys for tests
		pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		p2pkScript := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))
		p2wshScript := addrToScript(t, witnessScriptToAddress(t, p2pkScript, params))
		witness := wire.TxWitness{{0x01}}

		fqs, err := fullyQualifiedScriptFromTxData(params,
			p2wshScript, nil, witness, nil, nil)

		_assert.Error(t, err)
		_assert.True(t, strings.Contains(err.Error(), "failed to parse witnessScript ScriptData"))
		_assert.Nil(t, fqs)
	})

	// tests the error case when the redeemScript
	// in the scriptSig doesn't match the provided
	// script
	t.Run("validate against passed redeemScript", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		// Initalize public keys for tests
		pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		p2pkRedeemScript := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))
		p2shScript := addrToScript(t, redeemScriptToAddress(t, p2pkRedeemScript, params))
		scriptSig := []byte{0x01, 0x01}

		fqs, err := fullyQualifiedScriptFromTxData(params,
			p2shScript, scriptSig, nil, p2pkRedeemScript, nil)

		_assert.Error(t, err)

		_assert.True(t, strings.Contains(err.Error(), "no usable redeemScript found"))
		_assert.Nil(t, fqs)
	})

	// tests the error case when the scriptSig's
	// redeemScript is an invalid script
	t.Run("redeemScript should be valid", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		// Initalize public keys for tests
		pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		p2pkRedeemScript := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))
		p2shScript := addrToScript(t, redeemScriptToAddress(t, p2pkRedeemScript, params))
		scriptSig := []byte{0x01, 0x01}

		fqs, err := fullyQualifiedScriptFromTxData(params,
			p2shScript, scriptSig, nil, nil, nil)

		_assert.Error(t, err)

		_assert.True(t, strings.Contains(err.Error(), "failed to parse redeemScript ScriptData"))
		_assert.Nil(t, fqs)
	})

	// tests that the last element in the witness
	// is restricted to the provided witnessScript
	// when the spk is P2WSH
	t.Run("witnessScript should be valid", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		// Initalize public keys for tests
		pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)

		p2pkWitnessScript := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))
		p2wshScript := addrToScript(t, witnessScriptToAddress(t, p2pkWitnessScript, params))
		witness := wire.TxWitness{{0x01}}

		fqs, err := fullyQualifiedScriptFromTxData(params,
			p2wshScript, nil, witness, nil, p2pkWitnessScript)

		_assert.Error(t, err)
		_assert.True(t, strings.Contains(err.Error(), "failed find/check of witnessScript"))
		_assert.Nil(t, fqs)
	})
}

func TestNewFullyQualifiedScript(t *testing.T) {
	t.Run("test programming error - invalid p2wpkh solution", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		p2wpkh, err := hex.DecodeString("0014851a33a5ef0d4279bd5854949174e2c65b1d4500")
		_assert.NoError(t, err)

		p2wpkhData := &ScriptData{}
		err = p2wpkhData.Parse(p2wpkh, params)
		_assert.NoError(t, err)

		p2wpkhData.Solution[0] = nil

		fqs, err := newFullyQualifiedScript(params, p2wpkhData, nil, nil)
		_assert.Error(t, err)
		_assert.True(t, strings.Contains(err.Error(), "invalid p2wpkh ScriptData, abort"))
		_assert.Nil(t, fqs)
	})

	t.Run("test wrong witnessScript", func(t *testing.T) {
		params := &chaincfg.TestNet3Params

		pubKey1, err := hex.DecodeString("02844b0b849362e6cfc99c6dbcc63c9a546697c0015a62080470b0ce5e7d79c172")
		_assert.NoError(t, err)
		pubKey2, err := hex.DecodeString("034d4b15528378b8003fb08460c268382845e71e4f3d8babccac6a2a1a79df9a04")
		_assert.NoError(t, err)

		p2pk1 := addrToScript(t, pubKeyAddrFromBytes(t, pubKey1, params))
		p2wshScript1 := addrToScript(t, witnessScriptToAddress(t, p2pk1, params))

		p2pk2 := addrToScript(t, pubKeyAddrFromBytes(t, pubKey2, params))
		p2wshScript2 := addrToScript(t, witnessScriptToAddress(t, p2pk2, params))

		p2wshData1 := &ScriptData{}
		err = p2wshData1.Parse(p2wshScript1, params)
		_assert.NoError(t, err)

		p2wshData2 := &ScriptData{}
		err = p2wshData2.Parse(p2wshScript2, params)
		_assert.NoError(t, err)

		fqs, err := newFullyQualifiedScript(params, p2wshData1, nil, p2wshData2)
		_assert.Error(t, err)
		_assert.True(t, strings.Contains(err.Error(), "Based on previous information, the witnessScript seems incorrect."))
		_assert.Nil(t, fqs)
	})
}

func TestMultisigStackReader(t *testing.T) {
	params := &chaincfg.MainNetParams
	// these fixtures are special since there is always an OP_0
	// in front of them.
	t.Run(fmt.Sprintf("promiscuous fixture 0"), func(t *testing.T) {
		// see bip32wallet.PromiscuousTestCase1
		txHex := "01000000012450b115bf885dec4c4288395cb4cf2f1e514db1b477e39e0914bd370145995500000000b60000473044022026a46056c47a3a1abdba8e2ad155b5336967732c627072c1168687485f2abd56022039f0c55d72d5a9959a2b01dfaef59fc254e2c5443bfc0d27a8bfcb154a382e8001004c695221023f7d299050364c245b0f51ac102129b93db37ea56415524864d9b174445d65ed210317e8537ae93f15170b369f499d910011c0609c956025f86679a76f46cc5205e321033dcb8536d7e0c6a3a556f07accd55262dd4f452d4ca702e100557be6c26b096453aeffffffff0214b7f2050000000017a914247fc5c13b8b688244f1d8f118e15c3df62230f987a0860100000000001976a914d5034e455c98349e6c71a8f7f6f38463a5183d2288ac00000000"
		txBytes, err := hex.DecodeString(txHex)
		_assert.NoError(t, err)

		keyOrigins := make([]*KeyOrigin, 1)
		keyOrigins[0] = &KeyOrigin{}
		keyOrigins[0].Bip32, err = bip32util.NewPathFromString(`M/9999'/0/1`)
		_assert.NoError(t, err)

		inputs := make([]*InputSignData, 1)
		inputs[0], err = P2SHInput(123123123, "5221023f7d299050364c245b0f51ac102129b93db37ea56415524864d9b174445d65ed210317e8537ae93f15170b369f499d910011c0609c956025f86679a76f46cc5205e321033dcb8536d7e0c6a3a556f07accd55262dd4f452d4ca702e100557be6c26b096453ae", params)
		_assert.NoError(t, err)

		wireTx := &wire.MsgTx{}
		err = wireTx.Deserialize(bytes.NewReader(txBytes))
		_assert.NoError(t, err)

		scriptSigChunks, err := txscript.PushedData(wireTx.TxIn[0].SignatureScript)
		_assert.NoError(t, err)

		testChunks := removeLast(scriptSigChunks)

		sd := &ScriptData{}
		err = sd.Parse(inputs[0].RedeemScript, params)
		_assert.NoError(t, err)

		sigHashes := txscript.NewTxSigHashes(wireTx)
		checker, err := BitcoinCheckerCreator(wireTx, sigHashes, 0, 0)
		_assert.NoError(t, err)

		t.Run("works with promiscuous", func(t *testing.T) {
			reader := NewMultisigStackReader(PromiscuousMultisigFrameReader)
			sigs, pubs, err := reader(testChunks, sd, 0, checker)
			_assert.NoError(t, err)
			_assert.Len(t, sigs, 1)
			_assert.Len(t, pubs, 3)
		})

		t.Run("finds nothing with strict", func(t *testing.T) {
			reader := NewMultisigStackReader(StrictMultisigFrameReader)
			sigs, pubs, err := reader(testChunks, sd, 0, checker)
			_assert.NoError(t, err)
			_assert.Len(t, sigs, 0)
			_assert.Len(t, pubs, 3)
		})
	})

	t.Run(fmt.Sprintf("promiscuous fixture 1"), func(t *testing.T) {
		// see bip32wallet.PromiscuousTestCase2
		txHex := "0100000001a7d034389d454c5cb5401c9af9c65bf1d46563349fb6359c4e999ef8cf77a7da01000000b6004730440220600aab86e252fad71ecf9aeb97d11ad9b43e1fe3c17fc82853c7758abd588f8c02203580031bb9a06f169b9dda11a1fbab73aab2c18d54f215be460c68a3df98ef140100004c695221020c1e4f1e91237d468a967c38f826a899bfb41774ace010a542b6242f0b86badc210288204b009f0b4ac4a45801fd043d0daa7e23b2f71d75d78131e71f9f7a7785e02102f0a1d839c1cb0df637cdc2872a1b68923699b3d317f65b5b84ada58364c2a72c53aeffffffff020a4cf4050000000017a914b5ae3a9950fa66efa4aab2c21ce4a4275e7c95b487a0860100000000001976a914d5034e455c98349e6c71a8f7f6f38463a5183d2288ac00000000"
		txBytes, err := hex.DecodeString(txHex)
		_assert.NoError(t, err)

		keyOrigins := make([]*KeyOrigin, 1)
		keyOrigins[0] = &KeyOrigin{}
		keyOrigins[0].Bip32, err = bip32util.NewPathFromString(`M/9999'/0/4`)
		_assert.NoError(t, err)

		inputs := make([]*InputSignData, 1)
		inputs[0], err = P2SHInput(123123123, "5221020c1e4f1e91237d468a967c38f826a899bfb41774ace010a542b6242f0b86badc210288204b009f0b4ac4a45801fd043d0daa7e23b2f71d75d78131e71f9f7a7785e02102f0a1d839c1cb0df637cdc2872a1b68923699b3d317f65b5b84ada58364c2a72c53ae", params)
		_assert.NoError(t, err)

		wireTx := &wire.MsgTx{}
		err = wireTx.Deserialize(bytes.NewReader(txBytes))
		_assert.NoError(t, err)

		scriptSigChunks, err := txscript.PushedData(wireTx.TxIn[0].SignatureScript)
		_assert.NoError(t, err)

		testChunks := removeLast(scriptSigChunks)

		sd := &ScriptData{}
		err = sd.Parse(inputs[0].RedeemScript, params)
		_assert.NoError(t, err)

		sigHashes := txscript.NewTxSigHashes(wireTx)
		checker, err := BitcoinCheckerCreator(wireTx, sigHashes, 0, 0)
		_assert.NoError(t, err)

		t.Run("works with promiscuous", func(t *testing.T) {
			reader := NewMultisigStackReader(PromiscuousMultisigFrameReader)
			sigs, pubs, err := reader(testChunks, sd, 0, checker)
			_assert.NoError(t, err)
			_assert.Len(t, sigs, 1)
			_assert.Len(t, pubs, 3)
		})

		t.Run("finds nothing with strict", func(t *testing.T) {
			reader := NewMultisigStackReader(StrictMultisigFrameReader)
			sigs, pubs, err := reader(testChunks, sd, 0, checker)
			_assert.NoError(t, err)
			_assert.Len(t, sigs, 0)
			_assert.Len(t, pubs, 3)
		})
	})

	t.Run("ideal fixture", func(t *testing.T) {
		txHex := "0100000001137b71ca989f1fafebf4d98071e5c217752812e8622d2a2564aac5ebbf4919c701000000b7000000483045022100927534bd98f8120ab71488789b4721fb2501b0ef4384d6271ceb9eedd61508780220369c219415764366bbba23370b040986b51dd536da179eac69c5fa5790461f96014c695221024fec6f4389f3bb709a8d4f9fe40b91ff30db89e57f6973ec3bb1f307c92e85a72102cc252b73cd97c7e0f687bcebe93093de7780d96fb8812921cf8299eff9852c122103305c9c690b9e4bb2c745a4adbe1c64230dfd6089e8e98c035218686b6baf5aaf53aeffffffff020a4cf4050000000017a914501691f87899deb6fb2c31a3167888d647760b9c87a0860100000000001976a914d5034e455c98349e6c71a8f7f6f38463a5183d2288ac00000000"
		txBytes, err := hex.DecodeString(txHex)
		_assert.NoError(t, err)

		keyOrigins := make([]*KeyOrigin, 1)
		keyOrigins[0] = &KeyOrigin{}
		keyOrigins[0].Bip32, err = bip32util.NewPathFromString(`M/9999'/0/14`)
		_assert.NoError(t, err)

		inputs := make([]*InputSignData, 1)
		inputs[0], err = P2SHInput(5000000000, "5221024fec6f4389f3bb709a8d4f9fe40b91ff30db89e57f6973ec3bb1f307c92e85a72102cc252b73cd97c7e0f687bcebe93093de7780d96fb8812921cf8299eff9852c122103305c9c690b9e4bb2c745a4adbe1c64230dfd6089e8e98c035218686b6baf5aaf53ae", params)
		_assert.NoError(t, err)

		wireTx := &wire.MsgTx{}
		err = wireTx.Deserialize(bytes.NewReader(txBytes))
		_assert.NoError(t, err)

		scriptSigChunks, err := txscript.PushedData(wireTx.TxIn[0].SignatureScript)
		_assert.NoError(t, err)

		testChunks := removeLast(scriptSigChunks)

		sd := &ScriptData{}
		err = sd.Parse(inputs[0].RedeemScript, params)
		_assert.NoError(t, err)

		sigHashes := txscript.NewTxSigHashes(wireTx)
		checker, err := BitcoinCheckerCreator(wireTx, sigHashes, 0, 0)
		_assert.NoError(t, err)

		t.Run("works with promiscuous", func(t *testing.T) {
			reader := NewMultisigStackReader(PromiscuousMultisigFrameReader)
			sigs, pubs, err := reader(testChunks, sd, 0, checker)
			_assert.NoError(t, err)
			_assert.Len(t, sigs, 1)
			_assert.Len(t, pubs, 3)
		})

		t.Run("works with strict", func(t *testing.T) {
			reader := NewMultisigStackReader(StrictMultisigFrameReader)
			sigs, pubs, err := reader(testChunks, sd, 0, checker)
			_assert.NoError(t, err)
			_assert.Len(t, sigs, 1)
			_assert.Len(t, pubs, 3)
		})
	})
}

func TestPromiscuousBugCase(t *testing.T) {
	// this wasn't actually the problem, but
	// is a nice boilerplate for debugging MS extraction

	assert := _assert.New(t)
	txBytes, err := hex.DecodeString("01000000000101350918e3fa11186f374742a6f5ab0591ce0655cb534239282dedd5cf044baa4c0100000023220020f4fbb258bf40b11a7147652b08889b3bc3214307502f4be82b1cac1bc586f7cdffffffff02766907000000000017a91446936cd88d60bb5a4903eb617dc250268203feae8740420f000000000017a914207a77afa3965c6ba1eed5dfb4202b43d9c7b07287050000483045022100d663e40ac164ca75b544d25aec8abadd9806ec3f21956122d0b0ff94bf5c44ac0220182e9412eec5dc760d478534ec3b637de2c06d315c7c08c52f67475f5801c7fb010069522102420191439f1dca72a629bc81f954bb0f70120e5e79a80439cd9f9f692072c6ad210382f47c636ccfd514631b37463a89b69f756cfffb5310bd0b27e62250caf29baa2103a617f6812bbbced8ae6e0d708807370c9a3dbb1a55eec9d9432944e29008388d53ae00000000")
	assert.NoError(err)
	txInfo, err := btcutil.NewTxFromBytes(txBytes)
	assert.NoError(err)
	ws, err := hex.DecodeString("52" +
		"2102420191439f1dca72a629bc81f954bb0f70120e5e79a80439cd9f9f692072c6ad" +
		"210382f47c636ccfd514631b37463a89b69f756cfffb5310bd0b27e62250caf29baa" +
		"2103a617f6812bbbced8ae6e0d708807370c9a3dbb1a55eec9d9432944e29008388d" +
		"53ae")

	tx := txInfo.MsgTx()
	sigHashes := txscript.NewTxSigHashes(tx)
	var val int64 = 1487900
	checker, err := BitcoinCheckerCreator(tx, sigHashes, 0, val)
	assert.NoError(err)

	sig, err := hex.DecodeString("3045022100d663e40ac164ca75b544d25aec8abadd9806ec3f21956122d0b0ff94bf5c44ac0220182e9412eec5dc760d478534ec3b637de2c06d315c7c08c52f67475f5801c7fb01")
	assert.NoError(err)
	witness := wire.TxWitness{nil, nil, sig, ws}
	chunks := witness[0 : len(witness)-1]

	pkStrs := []string{
		"02420191439f1dca72a629bc81f954bb0f70120e5e79a80439cd9f9f692072c6ad",
		"0382f47c636ccfd514631b37463a89b69f756cfffb5310bd0b27e62250caf29baa",
		"03a617f6812bbbced8ae6e0d708807370c9a3dbb1a55eec9d9432944e29008388d",
	}
	pks := make([][]byte, len(pkStrs))
	for i := 0; i < len(pkStrs); i++ {
		pks[i], err = hex.DecodeString(pkStrs[i])
		assert.NoError(err)
	}

	res := PromiscuousMultisigFrameReader(checker, ws, chunks, pks, 1)
	assert.NotNil(res)
	assert.Len(res, 1)
}
