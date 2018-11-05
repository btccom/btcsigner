package wallet

import (
	"bytes"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/fastsha256"
	"github.com/pkg/errors"
)

// StackReader is an interface for extraction of
// a set of signatures and public keys from a set
// of chunks.
type StackReader func(chunks [][]byte, signScript *ScriptData, sigVersion int, checker CheckerInterface) (map[int]*TxSignature, map[int]*PublicKeyInfo, error)

// MultisigFrameReader is a type implementing the validation
// of multisig sigs, and association of a signature with
// it's public key. The sorting and association step can differ
// in strictness, hence the type
type MultisigFrameReader func(checker CheckerInterface, script []byte, sigs [][]byte, pubKeys [][]byte, sigVersion int) map[int]PairedSig

// ScriptReader is a type for encapsulating
// function pointers for supported script types
type ScriptReader struct {
	Multisig   StackReader
	PubKey     StackReader
	PubKeyHash StackReader
}

// NewScriptReader creates a ScriptReader, which ultimately is all the
// script types we intend to support.
func NewScriptReader(multisigFR MultisigFrameReader) *ScriptReader {
	return &ScriptReader{
		Multisig:   NewMultisigStackReader(multisigFR),
		PubKey:     PubKeyStackReader,
		PubKeyHash: PubKeyHashStackReader,
	}
}

// PubKeyStackReader implements the P2PK stack reader
func PubKeyStackReader(chunks [][]byte, signScript *ScriptData, sigVersion int, checker CheckerInterface) (map[int]*TxSignature, map[int]*PublicKeyInfo, error) {
	pubKeys := make(map[int]*PublicKeyInfo, 1)
	sigs := make(map[int]*TxSignature, 1)

	if len(chunks) == 1 {
		valid, err := checker.CheckSig(signScript.Script, signScript.Solution[0], chunks[len(chunks)-1], sigVersion)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed checksig")
		}

		pubKeys[0] = valid.pubKey
		sigs[0] = valid.sig
	}
	return sigs, pubKeys, nil
}

// PubKeyHashStackReader implements the P2PKH stack reader
func PubKeyHashStackReader(chunks [][]byte, signScript *ScriptData, sigVersion int, checker CheckerInterface) (map[int]*TxSignature, map[int]*PublicKeyInfo, error) {
	pubKeys := make(map[int]*PublicKeyInfo, 1)
	sigs := make(map[int]*TxSignature, 1)

	if len(chunks) == 2 {
		valid, err := checker.CheckSig(signScript.Script, chunks[len(chunks)-1], chunks[len(chunks)-2], sigVersion)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed checksig")
		}

		pubKeys[0] = valid.pubKey
		sigs[0] = valid.sig
	}
	return sigs, pubKeys, nil
}

// StrictMultisigFrameReader takes a set of sigs and keys, along with
// information about the script being checked, and attempts
// validate signatures in the order followed by CHECKMULTISIG.
// this lets us associate multi-signature sigs with the key
// that produced them. Only valid signatures are allowed.
func StrictMultisigFrameReader(checker CheckerInterface, script []byte,
	sigs [][]byte, pubKeys [][]byte, sigVersion int) map[int]PairedSig {

	ikey := 0
	isig := 0
	result := make(map[int]PairedSig, len(pubKeys))

	for isig < len(sigs) && ikey < len(pubKeys) {
		sig := sigs[len(sigs)-1-isig]
		valid, err := checker.CheckSig(script, pubKeys[len(pubKeys)-1-ikey], sig, sigVersion)
		if err == nil {
			result[len(pubKeys)-1-ikey] = PairedSig{key: valid.pubKey, sig: valid.sig}
			isig++
		}

		ikey++
	}

	return result
}

// PromiscuousMultisigFrameReader makes a transaction compatible with
// the partially signed scheme that bitcoin JS uses, in that it accepts
// signature chunks with extra OP_0 values. We still validate, we just
// advance isig when the signatures length is zero.
func PromiscuousMultisigFrameReader(checker CheckerInterface, script []byte,
	sigs [][]byte, pubKeys [][]byte, sigVersion int) map[int]PairedSig {

	ikey := 0
	isig := 0
	result := make(map[int]PairedSig, len(pubKeys))

	for isig < len(sigs) && ikey < len(pubKeys) {
		if len(sigs[len(sigs)-1-isig]) == 0 {
			ikey++
			isig++
			continue
		}

		valid, err := checker.CheckSig(script, pubKeys[len(pubKeys)-1-ikey], sigs[len(sigs)-1-isig], sigVersion)
		if err == nil {
			result[len(pubKeys)-1-ikey] = PairedSig{key: valid.pubKey, sig: valid.sig}
			isig++
		}

		ikey++
	}

	return result
}

// NewMultisigStackReader constructs the Multisig StackReader, as it
// depends on a MultisigFrameReader being available
func NewMultisigStackReader(frameReader MultisigFrameReader) StackReader {
	return func(chunks [][]byte, signScript *ScriptData, sigVersion int, checker CheckerInterface) (map[int]*TxSignature, map[int]*PublicKeyInfo, error) {
		n := len(signScript.Solution)

		sorted := frameReader(checker, signScript.Script, chunks, signScript.Solution, sigVersion)
		sigs := make(map[int]*TxSignature, n)
		pubKeys := make(map[int]*PublicKeyInfo, n)
		for i := 0; i < n; i++ {
			pair, isset := sorted[i]
			if !isset {
				keyInfo, err := ParsePublicKeyInfo(signScript.Solution[i])
				if err != nil {
					return nil, nil, errors.New("Invalid public key (no support for tolerating invalid-unused-multisig-key)")
				}
				pubKeys[i] = keyInfo
				continue
			}

			pubKeys[i] = pair.key
			sigs[i] = pair.sig
		}
		return sigs, pubKeys, nil
	}
}

// PairedSig captures a valid signature and
// the corresponding public key.
type PairedSig struct {
	key *PublicKeyInfo
	sig *TxSignature
}

// extractSigsFromChunks takes signScript and
// attempts to extract a map of [keyIdx => sig]
// and [keyIdx => key]. The function verifies
// signatures as they are found, and multisig's
// will be parsed in from stack-top to stack-last.
func extractSigsFromChunks(
	reader *ScriptReader,
	signScript *ScriptData, chunks [][]byte,
	checker CheckerInterface, sigVersion int) (
	map[int]*TxSignature, map[int]*PublicKeyInfo, error) {

	if signScript.Type == txscript.PubKeyHashTy {
		return reader.PubKeyHash(chunks, signScript, sigVersion, checker)
	} else if signScript.Type == txscript.PubKeyTy {
		return reader.PubKey(chunks, signScript, sigVersion, checker)
	} else if signScript.Type == txscript.MultiSigTy {
		return reader.Multisig(chunks, signScript, sigVersion, checker)
	}

	return nil, nil, errors.New("unsupported script")
}

// fullyQualifiedScript encapsulates all ScriptData
// information for a script from it's scriptPubKey,
// to the script that is actually signed/run (p2pk,p2pkh,etc)
// If an RS is present, it has been qualified against the SPK,
// If a WS is present, it was qualified against the SPK or RS.
// By solving this structure, we also learn sigVersion
type fullyQualifiedScript struct {
	spk        *ScriptData
	rs         *ScriptData
	ws         *ScriptData
	sign       *ScriptData
	sigVersion int
}

// newFullyQualifiedScript takes the ScriptData for the
// spk, rs, and ws. Any script-hash commitments are checked
// here.
func newFullyQualifiedScript(cfg *chaincfg.Params,
	spkData *ScriptData, rsData *ScriptData, wsData *ScriptData) (
	*fullyQualifiedScript, error) {

	sigVersion := 0
	signScript := spkData

	if signScript.Type == txscript.ScriptHashTy {
		if nil == rsData {
			return nil, errors.New("missing redeemScript")
		}

		if !bytes.Equal(spkData.Solution[0], btcutil.Hash160(rsData.Script)) {
			return nil, errors.New("redeemScript doesn't satisfy pay-to-script-hash")
		}

		signScript = rsData
	} else if nil != rsData {
		return nil, errors.New("superfluous redeemScript")
	}

	if signScript.Type == txscript.WitnessV0PubKeyHashTy {
		pkAddr, err := btcutil.NewAddressPubKeyHash(signScript.Solution[0], cfg)
		if err != nil {
			return nil, errors.Wrap(err, "invalid p2wpkh ScriptData, abort")
		}
		scriptSitu, _ := txscript.PayToAddrScript(pkAddr)

		signScript = &ScriptData{}
		err = signScript.Parse(scriptSitu, cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create p2wpkh ScriptData")
		}
		sigVersion = 1
	} else if signScript.Type == txscript.WitnessV0ScriptHashTy {
		if nil == wsData {
			return nil, errors.New("missing witnessScript")
		}

		// Qualify the redeemScript against the scriptPubKey
		witnessScriptHash := fastsha256.Sum256(wsData.Script)

		if !bytes.Equal(witnessScriptHash[:], signScript.Solution[0]) {
			return nil, errors.Errorf("Based on previous information, the witnessScript seems incorrect.")
		}

		sigVersion = 1
		signScript = wsData
	} else if nil != wsData {
		return nil, errors.New("superfluous witnessScript")
	}

	return &fullyQualifiedScript{
		sigVersion: sigVersion,
		spk:        spkData,
		rs:         rsData,
		ws:         wsData,
		sign:       signScript,
	}, nil
}

// fullyQualifiedScriptFromTxData extracts a FQS from
// primitive transaction data types - the txOut script
// (spk), the spending transaction's input script (scriptSig)
// and witness (witness), along with optional redeemScript
// and witnessScript. redeemScript/witnessScript are only
// required when the input is unsigned and the values are not
// available in the scriptSig/witness (respectively)
// After parsing this, the FQS is constructed.

// * NB: txscript.PushedData will OMIT any non-push opcodes.
//       this function assumes scriptSig is PUSHONLY.
//
func fullyQualifiedScriptFromTxData(cfg *chaincfg.Params,
	spk []byte, scriptSig []byte, witness wire.TxWitness,
	rsScript []byte, wsScript []byte) (*fullyQualifiedScript, error) {

	var wsData *ScriptData
	var rsData *ScriptData

	spkData := &ScriptData{}
	err := spkData.Parse(spk, cfg)
	if err != nil {
		return nil, errors.Wrap(err, "invalid scriptPubKey")
	}

	solution := spkData

	if solution.Type == txscript.ScriptHashTy {
		// Take all data pushed, redeemScript might be at the end.
		chunks, err := txscript.PushedData(scriptSig)
		if err != nil {
			return nil, errors.Wrap(err, "invalid scriptSig")
		}

		// Look for the redeemScript in signData or the input script.
		rs, err := findScriptAndCheck(chunks, rsScript)
		if err != nil {
			return nil, errors.Wrap(err, "no usable redeemScript found")
		}

		// Parse the redeemScript
		rsData = &ScriptData{}
		err = rsData.Parse(rs, cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse redeemScript ScriptData")
		}

		// Update solution with redeemScript for nested segwit
		solution = rsData
	}

	if solution.Type == txscript.WitnessV0ScriptHashTy {
		chunks := [][]byte(witness)
		// Look for the witnessScript in signData or the input script.
		ws, err := findScriptAndCheck(chunks, wsScript)
		if err != nil {
			return nil, errors.Wrap(err, "failed find/check of witnessScript")

		}

		// Parse the witnessScript
		wsData = &ScriptData{}
		err = wsData.Parse(ws, cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse witnessScript ScriptData")
		}
	}

	return newFullyQualifiedScript(cfg, spkData, rsData, wsData)
}

// extractStack takes a scriptSig and witness, and
// based off the current context will extract the stack
// run by our signScript by determining if p2sh/witness
// and removing scriptHash commitments, leaving only
// our bare script stack
func (fqs *fullyQualifiedScript) extractStack(scriptSig []byte, witness wire.TxWitness) ([][]byte, error) {
	sigChunks, err := txscript.PushedData(scriptSig)
	if err != nil {
		return nil, err
	}

	solution := fqs.spk
	if solution.Type == txscript.ScriptHashTy {
		if len(sigChunks) > 0 && bytes.Equal(sigChunks[len(sigChunks)-1], fqs.rs.Script) {
			sigChunks = removeLast(sigChunks)
		}
		solution = fqs.rs
	}

	if solution.Type == txscript.WitnessV0PubKeyHashTy {
		sigChunks = [][]byte(witness)
	} else if solution.Type == txscript.WitnessV0ScriptHashTy {
		sigChunks = [][]byte(witness)
		if len(sigChunks) > 0 && bytes.Equal(sigChunks[len(sigChunks)-1], fqs.ws.Script) {
			sigChunks = removeLast(sigChunks)
		}
	}

	return sigChunks, nil
}

// encodeStack takes a stack and produces the txin's
// scriptSig and witness fields. stack is essentially
// encoded in a different place if it's witness, and
// for rs/ws, the script needs to be the first pop
// from the stack.
func (fqs *fullyQualifiedScript) encodeStack(stack [][]byte) ([]byte, wire.TxWitness, error) {
	p2sh := false

	sigData := stack
	var witnessData [][]byte
	var err error

	solution := fqs.spk
	if solution.Type == txscript.ScriptHashTy {
		p2sh = true
		solution = fqs.rs
	}

	if solution.Type == txscript.WitnessV0PubKeyHashTy {
		witnessData = stack
		sigData = [][]byte{}
	} else if solution.Type == txscript.WitnessV0ScriptHashTy {
		witnessData = stack
		witnessData = append(witnessData, fqs.ws.Script)
		sigData = [][]byte{}
		solution = fqs.ws
	}

	if p2sh {
		sigData = append(sigData, fqs.rs.Script)
	}

	script, err := PushDataToScript(sigData)
	if err != nil {
		return nil, nil, err
	}

	return script, wire.TxWitness(witnessData), nil
}

// isSegwit returns whether the scriptPubKey or redeemScript
// is a witness program.
func (fqs *fullyQualifiedScript) isSegwit() bool {
	if fqs.spk.Type == txscript.ScriptHashTy {
		return txscript.IsWitnessProgram(fqs.rs.Script)
	}

	return txscript.IsWitnessProgram(fqs.spk.Script)
}

// extractScriptAndSigChunks takes a pkScript, a sigScript (possibly empty), a witness (possibly
// empty), and a InputSignData struct, and returns the SigVersion, the chunks
// of data containing signatures (from scriptSig or witness), the *ScriptData
// for the scriptPubKey, redeemScript, and witnessScript, and also the 'sign
// script' which is directly signed in the signature hash.
func extractScriptAndSigChunks(params *chaincfg.Params, scriptPubKey []byte, scriptSig []byte, witness wire.TxWitness, rsScript []byte, wsScript []byte) (
	[][]byte, *fullyQualifiedScript, error) {

	if !txscript.IsPushOnlyScript(scriptSig) {
		return nil, nil, errors.New("scriptSig must be push only")
	}

	fqs, err := fullyQualifiedScriptFromTxData(params, scriptPubKey, scriptSig, witness, rsScript, wsScript)
	if err != nil {
		return nil, nil, err
	}

	if !fqs.sign.CanSign() {
		return nil, nil, errors.Errorf("script not supported, was %s", fqs.spk.Type.String())
	}

	sigChunks, err := fqs.extractStack(scriptSig, witness)
	if err != nil {
		return nil, nil, err
	}

	return sigChunks, fqs, nil
}

// This function makes it convenient to take the redeemScript/witnessScript
// from either a decompiled scriptSig/witness or if provided as the commitedScript.
// If the committed script is provided and the scriptData non-empty, they are
// compared for consistency.
func findScriptAndCheck(scriptData [][]byte, committedScript []byte) ([]byte, error) {
	if len(scriptData) > 0 {
		elem := scriptData[len(scriptData)-1]

		if committedScript != nil {
			if !bytes.Equal(elem, committedScript) {
				return nil, errors.New("last element of chunks didn't match provided script")
			}
		}
		return elem, nil
	}

	if committedScript == nil {
		return nil, errors.New("no committed script was provided, and scriptData was empty")
	}

	return committedScript, nil
}

// removes last []byte from a [][]byte
func removeLast(chunks [][]byte) [][]byte {
	length := len(chunks)
	if length > 0 {
		return chunks[:length-1]
	}

	return make([][]byte, 0)
}
