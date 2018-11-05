package bip32util

import (
	"encoding/binary"
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
)

var (
	// ErrKeyPathMismatch is produced by Key.init when
	// the path doesn't match an attribute of the key.
	ErrKeyPathMismatch = errors.New("key matched with wrong path, both should equal")

	// ErrBadRootKey is produced by when the provided
	// key doesn't match the expected attributes of a _root_
	// BIP32 key.
	ErrBadRootKey = errors.New("root key must have a depth and parent fingerprint of 0")

	// ErrKeyIsAlreadyPublic is returned when a codepath
	// requests a public key be converted to a public key.
	ErrKeyIsAlreadyPublic = errors.New("key is already public")
)

// NewBip32MasterKey will initialize a Key from a provided ExtendedKey and Path
func NewBip32MasterKey(key *hdkeychain.ExtendedKey) (*Key, error) {
	if key.ParentFingerprint() != 0 || key.Depth() != 0 {
		return nil, ErrBadRootKey
	}

	if key.IsPrivate() {
		return NewBip32Key(key, NewPrivatePath())
	}

	return NewBip32Key(key, NewPublicPath())
}

// NewBip32Key will initialize a Key from a provided ExtendedKey and Path
func NewBip32Key(key *hdkeychain.ExtendedKey, path *Path) (*Key, error) {
	if path.IsPrivate() != key.IsPrivate() {
		return nil, ErrKeyPathMismatch
	}

	if path.Depth() != int(key.Depth()) {
		return nil, ErrKeyPathMismatch
	}

	return &Key{
		Key:  key,
		Path: path,
	}, nil
}

// overrideBip32Sequence takes a key and the new addrIdx, and
// forceably overrides the address index / sequence field.
// It does this by overwriting bytes in the serialized key
// and reinitializing it.
func overrideBip32Sequence(k *hdkeychain.ExtendedKey, addrIdx uint32) (*hdkeychain.ExtendedKey, error) {
	// Serialize the base58 key, and decode the resulting base58-check string.
	decoded, version, err := base58.CheckDecode(k.String())
	if err != nil {
		return nil, err
	}

	// Ensure the BIP32 key has the new address-index (last derivation index)
	binary.BigEndian.PutUint32(decoded[8:12], addrIdx)

	encoded := base58.CheckEncode(decoded, version)
	newKey, err := hdkeychain.NewKeyFromString(encoded)
	if err != nil {
		return nil, err
	}

	return newKey, nil
}

// Key captures a BIP32 key, which is somewhat lossy
// in the information it includes, with the entire
// derivation path.
type Key struct {
	Key  *hdkeychain.ExtendedKey
	Path *Path
}

// ForceNewPath overrides the current key's path, used
// for btc.com's different-key-by-walletID when the user
// picks a key index. Our paths include the walletID,
// which is hidden from the user.
func (k *Key) ForceNewPath(path *Path) error {
	if !k.IsPrivate() && path.IsPrivate() {
		return errors.New("path is for private key, but key is public")
	}

	var addrIdx uint32
	if len(path.Path) > 0 {
		addrIdx = path.Path[len(path.Path)-1]
	}

	key := k.Key
	if k.IsPrivate() && !path.IsPrivate() {
		var err error
		key, err = k.Key.Neuter()
		if err != nil {
			return err
		}
	}

	newKey, err := overrideBip32Sequence(key, addrIdx)
	if err != nil {
		return err
	}

	*k.Key = *newKey
	k.Path = path

	return nil
}

// Child takes a sequence number and derives a child
// key. Called repetitively to derive a path.
func (k *Key) Child(sequence uint32) (*Key, error) {
	newPath, err := k.Path.Child(sequence)
	if err != nil {
		return nil, err
	}

	newKey, err := k.Key.Child(sequence)
	if err != nil {
		return nil, err
	}

	return &Key{newKey, newPath}, nil
}

// IsPrivate returns true if the key is private,
// false if public.
func (k *Key) IsPrivate() bool {
	return k.Key.IsPrivate()
}

// ToPublic converts the key and it's path to
// the public form, or returns an error if the
// Key is already public.
func (k *Key) ToPublic() (*Key, error) {
	if !k.IsPrivate() {
		return nil, ErrKeyIsAlreadyPublic
	}

	key, _ := k.Key.Neuter()
	path := k.Path.ToPublic()

	return NewBip32Key(key, path)
}
