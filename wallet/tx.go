package wallet

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/pkg/errors"
	"sync"
)

// allowedP2sh represents the list of script types
// we are prepared to accept if the script is P2SH.
var allowedP2sh = map[txscript.ScriptClass]bool{
	txscript.WitnessV0PubKeyHashTy: true,
	txscript.WitnessV0ScriptHashTy: true,
	txscript.PubKeyHashTy:          true,
	txscript.PubKeyTy:              true,
	txscript.MultiSigTy:            true,
}

// canSign is the list of scriptTypes we can directly
// sign
var canSign = map[txscript.ScriptClass]bool{
	txscript.PubKeyHashTy: true,
	txscript.PubKeyTy:     true,
	txscript.MultiSigTy:   true,
}

// SignerFactory is a factory function that produces a TxSigner
// for the provided transaction. It should take care of configuring
// the signer.
type SignerFactory func(tx *wire.MsgTx) *TxSigner

// NewSignerFactory produces a SignerFactory out of a Network.
func NewSignerFactory(network *Network, scriptReader ScriptReader) SignerFactory {
	return func(tx *wire.MsgTx) *TxSigner {
		return NewTxSigner(network.Params, tx, network.SegwitEnabled, network.CheckerCreator, &scriptReader)
	}
}

// IsAllowedP2shType returns whether the provided
// script type is a valid P2SH redeem script.
func IsAllowedP2shType(sc txscript.ScriptClass) bool {
	_, ok := allowedP2sh[sc]
	return ok
}

// CanSignType returns whether the provided script
// type can be directly signed.
func CanSignType(sc txscript.ScriptClass) bool {
	_, ok := canSign[sc]
	return ok
}

// NewInputSignData takes a txOut/rs/ws, and checks they are
// associated with eachother.
func NewInputSignData(txOut *wire.TxOut, rs []byte, ws []byte) *InputSignData {
	signData := &InputSignData{}
	signData.TxOut = txOut
	if len(rs) > 0 {
		signData.RedeemScript = rs
	}
	if len(ws) > 0 {
		signData.WitnessScript = ws
	}
	return signData
}

// InputSignData is the data required to verify/sign a
// transaction.
type InputSignData struct {
	TxOut *wire.TxOut

	RedeemScript  []byte
	WitnessScript []byte
}

// ParseScript takes a script and returns some information
// about it - 1, the script type. If unparsable, this will
// be nonstandard. 2 - the 'solution' - whether a script hash
// of some redeemScript, or a pubKeyHash, or a pubkey, or
// the hash of a hashlock - this represents the element we
// need to solve in this snippet. 3. The list of addresses.
// Most likely, the second field is redundant with this field..
// 4. the number of signatures is returned.
func ParseScript(pkScript []byte, chainParams *chaincfg.Params) (txscript.ScriptClass, [][]byte, []btcutil.Address, int, error) {
	scriptType, vAddr, nReqSigs, err := txscript.ExtractPkScriptAddrs(pkScript, chainParams)
	if err != nil {
		return txscript.NonStandardTy, nil, nil, 0, err
	}

	switch scriptType {
	case txscript.ScriptHashTy, txscript.WitnessV0ScriptHashTy, txscript.WitnessV0PubKeyHashTy, txscript.PubKeyTy, txscript.PubKeyHashTy:
		if len(vAddr) != 1 {
			if scriptType == txscript.PubKeyTy {
				return txscript.NonStandardTy, nil, nil, 0, errors.Errorf("Parsed script was %s but had an invalid public key", txscript.PubKeyTy.String())
			}

			return txscript.NonStandardTy, nil, nil, 0, errors.Errorf("Parsed script was %s but was invalid", scriptType.String())
		}

		vSol := make([][]byte, 1)
		vSol[0] = vAddr[0].ScriptAddress()
		return scriptType, vSol, vAddr, nReqSigs, nil
	case txscript.MultiSigTy:
		nPubkey, _, err := txscript.CalcMultiSigStats(pkScript)
		if err != nil {
			return txscript.NonStandardTy, nil, nil, 0, err
		}
		if len(vAddr) != nPubkey {
			return txscript.NonStandardTy, nil, nil, 0, errors.Errorf("An invalid public key was found in the multisig script")
		}
		vSol := make([][]byte, nPubkey)
		for i := 0; i < nPubkey; i++ {
			vSol[i] = vAddr[i].ScriptAddress()
		}
		return scriptType, vSol, vAddr, nReqSigs, nil
	default:
		return txscript.NonStandardTy, nil, nil, 0, errors.New("Unsupported script")
	}
}

// ScriptData captures state about a particular
// script - it's addresses/solution, the number
// of sigs required to sign, etc.
type ScriptData struct {
	Type      txscript.ScriptClass
	NumSigs   int
	Script    []byte
	Solution  [][]byte
	Addresses []btcutil.Address
}

// CanSign returns whether the script type is
// immediately signable, ie, not a script-hash
// type
func (sd *ScriptData) CanSign() bool {
	return CanSignType(sd.Type)
}

// IsAllowedP2SH returns whether the script type is
// immediately signable, or is a witness type (which
// can be nested in P2SH)
func (sd *ScriptData) IsAllowedP2SH() bool {
	return IsAllowedP2shType(sd.Type)
}

// Parse initializes the ScriptData struct with
// information about a script after calling ParseScript.
// An error is returned if this step fails.
func (sd *ScriptData) Parse(pkScript []byte, params *chaincfg.Params) error {
	scriptType, vSol, vAddr, nSigs, err := ParseScript(pkScript, params)
	if err != nil {
		return err
	}

	sd.Type = scriptType
	sd.Script = pkScript
	sd.Solution = vSol
	sd.NumSigs = nSigs
	sd.Addresses = vAddr

	return nil
}

// CheckerCreator - this declaration is for convenience
// while specifying the type in various places
type CheckerCreator func(tx *wire.MsgTx, sigHashes *txscript.TxSigHashes, nIn int, value int64) (CheckerInterface, error)

// NewTxSigner is a low level constructor for a TxSigner.
// It takes the params, tx, whether segwit is enabled, and
// the checkerCreator, and initializes the instance. It does
// not return errors at the moment, this only happens from
// an input.
func NewTxSigner(params *chaincfg.Params, tx *wire.MsgTx, segwitEnabled bool, checkerCreator CheckerCreator, reader *ScriptReader) *TxSigner {
	return &TxSigner{
		params:         params,
		tx:             tx,
		segwitEnabled:  segwitEnabled,
		vSigner:        make(map[int]*InputSigner, len(tx.TxIn)),
		checkerCreator: checkerCreator,
		scriptReader:   reader,
	}
}

// TxSigner contains the state for signing
type TxSigner struct {
	sync.RWMutex
	params         *chaincfg.Params
	vSigner        map[int]*InputSigner
	tx             *wire.MsgTx
	segwitEnabled  bool
	checkerCreator CheckerCreator
	scriptReader   *ScriptReader
	sigHashes      *txscript.TxSigHashes
}

// Build reconstructs a Tx message by applying
// any new signatures to the signature script / witness
func (signer *TxSigner) Build() (*wire.MsgTx, error) {
	signer.RLock()
	defer signer.RUnlock()
	txCopy := *signer.tx

	for i := 0; i < len(txCopy.TxIn); i++ {
		if input, exists := signer.vSigner[i]; exists {
			sig, wit, err := input.SerializeSigs()
			if err != nil {
				return nil, errors.New("Fatal error - unable to serialize signatures")
			}

			txCopy.TxIn[i].SignatureScript = sig
			txCopy.TxIn[i].Witness = wit
		}
	}

	return &txCopy, nil
}

// GetSigHashes returns the TxSigHashes value
// for the transaction. The value is cached so
// multiple calls should return the same result.
func (signer *TxSigner) GetSigHashes() *txscript.TxSigHashes {
	if nil == signer.sigHashes {
		signer.sigHashes = txscript.NewTxSigHashes(signer.tx)
	}

	return signer.sigHashes
}

func (signer *TxSigner) makeInput(nInput int, signData *InputSignData) (*InputSigner, error) {
	inputSigner := &InputSigner{
		segwitEnabled: signer.segwitEnabled,
		reader:        signer.scriptReader,
	}

	sigHashes := signer.GetSigHashes()
	checker, err := signer.checkerCreator(signer.tx, sigHashes, nInput, signData.TxOut.Value)
	if err != nil {
		return nil, err
	}

	err = inputSigner.Init(signer.params, sigHashes, checker, signer.tx, nInput, signData)
	if err != nil {
		return nil, err
	}

	return inputSigner, nil
}

// Input takes nInput, accesses that input, and initializes
// the InputSigner. The InputSignData element is used to
// supplement script information for a completely unsigned
// transaction. The scriptPubKey ultimately drives what
// information is required
func (signer *TxSigner) Input(nInput int, signData *InputSignData) (*InputSigner, error) {
	signer.Lock()
	defer signer.Unlock()

	if inputSigner, exists := signer.vSigner[nInput]; exists {
		return inputSigner, nil
	}

	numInputs := len(signer.tx.TxIn)
	if nInput < 0 || nInput > numInputs {
		return nil, errors.Errorf("Requested out of range input %d, but transaction has %d", nInput, numInputs)
	}

	inputSigner, err := signer.makeInput(nInput, signData)
	if err != nil {
		return nil, err
	}

	signer.vSigner[nInput] = inputSigner

	return inputSigner, nil
}

// InputSigner exposes an API for extracting an inputs
// signatures, signing, and verifying.
type InputSigner struct {
	sync.RWMutex
	tx            *wire.MsgTx
	nInput        int
	segwitEnabled bool
	reader        *ScriptReader
	fqs           *fullyQualifiedScript
	checker       CheckerInterface
	sigHashes     *txscript.TxSigHashes
	signData      *InputSignData
	keyClosure    txscript.KeyClosure
	sigs          map[int]*TxSignature
	keys          map[int]*PublicKeyInfo
}

// init initializes an InputSigner struct by taking
// the transactions information, a network-specific
// CheckerInterface, the InputSignData (only necessary
// if the input is totally unsigned), and a KeyClosure
// to use while signing.
func (input *InputSigner) Init(params *chaincfg.Params, txSigHashes *txscript.TxSigHashes, checker CheckerInterface,
	tx *wire.MsgTx, nInput int, inputData *InputSignData) error {

	input.Lock()
	defer input.Unlock()
	if nInput < 0 || nInput > len(tx.TxIn) {
		return errors.Errorf("Input %d does not exist in transaction", nInput)
	}

	// extract fqs, and then extract the sigChunks for that
	sigChunks, fqs, err := extractScriptAndSigChunks(params,
		inputData.TxOut.PkScript, tx.TxIn[nInput].SignatureScript, tx.TxIn[nInput].Witness,
		inputData.RedeemScript, inputData.WitnessScript)
	if err != nil {
		return err
	}

	if !input.segwitEnabled && fqs.isSegwit() {
		return errors.Errorf("detected segwit input, though it is not enabled")
	}

	// build map[keyIdx]sig and map[keyIdx]key
	sigs, keys, err := extractSigsFromChunks(
		input.reader, fqs.sign, sigChunks,
		checker, fqs.sigVersion)
	if err != nil {
		return err
	}

	input.tx = tx
	input.nInput = nInput
	input.fqs = fqs
	input.checker = checker
	input.signData = inputData
	input.sigHashes = txSigHashes
	input.sigs = sigs
	input.keys = keys

	return nil
}

// SignFinal takes a hashType, loops over the inputs addresses,
// and adds a signature for each key that the signer has access
// to. It will error if the
func (input *InputSigner) SignFinal(hashType txscript.SigHashType, signer SignatureProvider) ([]*TxSignature, error) {
	input.Lock()
	defer input.Unlock()
	signed, sigs, err := input.sign(hashType, signer)
	if err != nil {
		return nil, err
	}
	if signed != input.fqs.sign.NumSigs {
		return nil, errors.Errorf("Unable to sign input %d", input.nInput)
	}
	return sigs, nil
}

// Sign takes a hashType, loops over the inputs
// addresses, and adds a signature for each key
// that the keyClosure has access to.
func (input *InputSigner) Sign(hashType txscript.SigHashType, signer SignatureProvider) ([]*TxSignature, error) {
	input.Lock()
	defer input.Unlock()
	_, sigs, err := input.sign(hashType, signer)
	return sigs, err
}

func (input *InputSigner) sign(hashType txscript.SigHashType, signer SignatureProvider) (int, []*TxSignature, error) {
	sigs := make([]*TxSignature, 0, len(input.fqs.sign.Addresses))
	signed := 0

	for i, solution := range input.fqs.sign.Addresses {
		if input.sigs[i] != nil {
			signed++
			continue
		}

		if signed >= input.fqs.sign.NumSigs {
			continue
		}

		hash, err := input.checker.GetSigHash(input.fqs.sign.Script, hashType, input.fqs.sigVersion)
		if err != nil {
			return 0, nil, err
		}

		pub, signature, known, err := signer.Sign(solution, hash)
		if !known {
			continue
		}
		if err != nil {
			return 0, nil, err
		}

		// public key hash scripts don't have this
		if input.keys[i] == nil {
			info, err := ParsePublicKeyInfo(pub.SerializeCompressed())
			if err != nil {
				return 0, nil, errors.Wrap(err, "cannot parse public key info")
			}
			input.keys[i] = info
		}

		input.sigs[i] = &TxSignature{
			HashType:  hashType,
			Signature: signature,
		}
		sigs = append(sigs, input.sigs[i])
		signed++
	}

	return signed, sigs, nil
}

// SerializeSigs regenerates the stack for the signScript
// with whatever sigs/keys are present on input. It then
// passes this to fqs.encodeStack to adjust for p2sh/p2wsh
// to produce the stack
func (input *InputSigner) SerializeSigs() ([]byte, [][]byte, error) {
	input.RLock()
	defer input.RUnlock()

	stack, err := serializeSolution(input.fqs.sign.Type, input.sigs, input.keys)
	if err != nil {
		return nil, nil, err
	}
	return input.fqs.encodeStack(stack)
}

// serializeSolution takes a scriptType, and a map of keys/sigs (by
// key index), and produces a vector of byte vectors representing
// the stack for the operation
func serializeSolution(scriptType txscript.ScriptClass, sigs map[int]*TxSignature, pubkeys map[int]*PublicKeyInfo) ([][]byte, error) {
	var data [][]byte
	nKeys := len(pubkeys)

	switch scriptType {
	case txscript.PubKeyTy:
		if len(sigs) == 1 {
			data = make([][]byte, 1)
			data[0] = sigs[0].Serialize()
		}
	case txscript.PubKeyHashTy:
		if len(sigs) == 1 && nKeys == 1 {
			pubKey, _ := pubkeys[0].Serialize()
			data = make([][]byte, 2)
			data[0] = sigs[0].Serialize()
			data[1] = pubKey
		}
	case txscript.MultiSigTy:
		data = append(data, []byte{})
		for i := 0; i < nKeys; i++ {
			if sigs[i] != nil {
				data = append(data, sigs[i].Serialize())
			}
		}
	default:
		return nil, errors.New("Unsupported script type used in serializeSolution")
	}

	return data, nil
}

// ParseTxSignature takes a byte vector and parses
// a TxSignature struct
func ParseTxSignature(sig []byte) (*TxSignature, error) {
	if len(sig) < 1 {
		return nil, errors.New("TxSignature too short")
	}

	hashType := txscript.SigHashType(sig[len(sig)-1])
	sigBytes := sig[:len(sig)-1]
	signature, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
	if err != nil {
		return nil, err
	}

	return &TxSignature{
		HashType:  hashType,
		Signature: signature,
	}, nil
}

// TxSignature captures the parsed btcce.Signature
// and signatures hashtype.
type TxSignature struct {
	HashType  txscript.SigHashType
	Signature *btcec.Signature
}

// Serialize will take the hashType and *btcec.Signature and
// produce the txin signature
func (sigInfo *TxSignature) Serialize() []byte {
	ecSig := sigInfo.Signature.Serialize()
	ecSig = append(ecSig, byte(int(sigInfo.HashType)))
	return ecSig
}

// ParsePublicKeyInfo takes keyBytes and produces
// a PublicKeyInfo struct
func ParsePublicKeyInfo(keyBytes []byte) (*PublicKeyInfo, error) {
	if len(keyBytes) < 33 {
		return nil, errors.New("Invalid length of public key")
	}

	var pkFormat btcutil.PubKeyFormat
	switch keyBytes[0] {
	case 0x02, 0x03:
		pkFormat = btcutil.PKFCompressed
	case 0x04:
		pkFormat = btcutil.PKFUncompressed
	case 0x06, 0x07:
		pkFormat = btcutil.PKFHybrid
	default:
		return nil, errors.New("Invalid prefix for public key")
	}

	pubKey, err := btcec.ParsePubKey(keyBytes, btcec.S256())
	if err != nil {
		return nil, errors.Wrap(err, "parse PublicKeyInfo failed")
	}

	return &PublicKeyInfo{
		Format: pkFormat,
		Key:    pubKey,
	}, nil
}

// PublicKeyInfo encapsulates an extracted btcec.PublicKey
// and the public key's serialized prefix.
type PublicKeyInfo struct {
	Format btcutil.PubKeyFormat
	Key    *btcec.PublicKey
}

// Serialize will take the known key format and btcec.PublicKey and
// produce the serialized key.
func (keyInfo *PublicKeyInfo) Serialize() ([]byte, error) {
	switch keyInfo.Format {
	case btcutil.PKFHybrid:
		return keyInfo.Key.SerializeHybrid(), nil
	case btcutil.PKFCompressed:
		return keyInfo.Key.SerializeCompressed(), nil
	case btcutil.PKFUncompressed:
		return keyInfo.Key.SerializeHybrid(), nil
	default:
		return nil, errors.New("unsupported public key format")
	}
}

// PushDataToScript takes a list of byte vectors and produces
// a script that is PUSHONLY compliant.
func PushDataToScript(pushDatas [][]byte) ([]byte, error) {
	builder := txscript.NewScriptBuilder()
	for i, l := 0, len(pushDatas); i < l; i++ {
		builder.AddData(pushDatas[i])
	}
	return builder.Script()
}
