package bip32util

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestForcePathPrivateToPublic(t *testing.T) {
	params := &chaincfg.TestNet3Params
	seedHex := "4242424242424242424242424242424242424242424242424242424242424242"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Invalid hex seed: %s", err.Error())
		return
	}

	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Errorf("Invalid seed: %s", err.Error())
		return
	}

	path, err := NewPathFromString("m")
	assert.NoError(t, err)

	b32 := &Key{
		Key:  key,
		Path: path,
	}

	newpath, err := NewPathFromString("M")
	assert.NoError(t, err)

	err = b32.ForceNewPath(newpath)
	assert.NoError(t, err)
	assert.False(t, b32.Key.IsPrivate())
	assert.Equal(t, "M", b32.Path.String())
}

func TestForcePathPublicToPrivate(t *testing.T) {
	params := &chaincfg.TestNet3Params
	seedHex := "4242424242424242424242424242424242424242424242424242424242424242"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Invalid hex seed: %s", err.Error())
		return
	}

	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Errorf("Invalid seed: %s", err.Error())
		return
	}

	key, _ = key.Neuter()

	path, err := NewPathFromString("M")
	assert.NoError(t, err)

	b32 := &Key{
		Key:  key,
		Path: path,
	}

	newpath, err := NewPathFromString("m")
	assert.NoError(t, err)

	err = b32.ForceNewPath(newpath)
	assert.Error(t, err)
	assert.EqualError(t, err, "path is for private key, but key is public")
}

func TestForcePathWillSetAddressIndex(t *testing.T) {
	params := &chaincfg.TestNet3Params
	seedHex := "4242424242424242424242424242424242424242424242424242424242424242"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Invalid hex seed: %s", err.Error())
		return
	}

	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Errorf("Invalid seed: %s", err.Error())
		return
	}

	derived, err := key.Child(123)
	assert.NoError(t, err)
	assert.Nil(t, err)
	assert.IsType(t, hdkeychain.ExtendedKey{}, *derived)

	p, err := NewPathFromString("m/123")
	assert.NoError(t, err)

	b32 := &Key{
		Key:  key,
		Path: p,
	}

	// The final path index will match our HD key sequence.
	assert.Equal(t, uint32(123), b32.Path.Path[len(b32.Path.Path)-1])

	// Force the path to m/888888
	newpath, err := NewPathFromString("m/888888")
	assert.NoError(t, err)

	err = b32.ForceNewPath(newpath)
	assert.NoError(t, err)
	assert.Equal(t, newpath, b32.Path)

	// Look at the original key, and check its serialization had 123
	origExtKey, _, err := base58.CheckDecode(derived.String())
	assert.NoError(t, err)
	assert.NotNil(t, origExtKey)

	origIdx := binary.BigEndian.Uint32(origExtKey[8:12])
	assert.Equal(t, uint32(123), origIdx)

	// Look at the new key, and check its serialization has 888888
	forcedExtKey, _, err := base58.CheckDecode(b32.Key.String())
	assert.NoError(t, err)
	assert.NotNil(t, forcedExtKey)
	assert.Equal(t, uint32(888888), b32.Path.Path[len(b32.Path.Path)-1])

	forcedIdx := binary.BigEndian.Uint32(forcedExtKey[8:12])
	assert.Equal(t, uint32(888888), forcedIdx)
}

func TestKeyToPublic(t *testing.T) {
	params := &chaincfg.TestNet3Params
	seedHex := "4242424242424242424242424242424242424242424242424242424242424242"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Invalid hex seed: %s", err.Error())
		return
	}

	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Errorf("Invalid seed: %s", err.Error())
		return
	}

	path, err := NewPathFromString("m")
	assert.NoError(t, err)

	b32 := &Key{
		Key:  key,
		Path: path,
	}

	pub, err := b32.ToPublic()
	assert.NoError(t, err)
	assert.False(t, pub.Path.fPriv)
	assert.False(t, pub.Path.IsPrivate())
	assert.False(t, pub.Key.IsPrivate())
}

func TestKeyPublicToPublicFails(t *testing.T) {
	params := &chaincfg.TestNet3Params
	seedHex := "4242424242424242424242424242424242424242424242424242424242424242"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Invalid hex seed: %s", err.Error())
		return
	}

	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Errorf("Invalid seed: %s", err.Error())
		return
	}

	path, err := NewPathFromString("m")
	assert.NoError(t, err)

	b32 := &Key{
		Key:  key,
		Path: path,
	}

	pub, err := b32.ToPublic()
	assert.NoError(t, err)
	assert.False(t, pub.Path.fPriv)
	assert.False(t, pub.Path.IsPrivate())
	assert.False(t, pub.Key.IsPrivate())
	assert.False(t, pub.IsPrivate())
}

func TestBip32KeyRootCases(t *testing.T) {
	params := &chaincfg.MainNetParams
	seedHex := "4242424242424242424242424242424242424242424242424242424242424242"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Errorf("Invalid hex seed: %s", err.Error())
		return
	}

	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		t.Errorf("Invalid seed: %s", err.Error())
		return
	}

	fixtures := []struct {
		path     string
		expected bool
	}{
		{"m", true},
		{"M", false},
	}

	for i := 0; i < len(fixtures); i++ {
		desc := fmt.Sprintf("key case %d", i)
		t.Run(desc, func(t *testing.T) {
			pathStr := fixtures[i].path
			expected := fixtures[i].expected

			path, err := NewPathFromString(pathStr)
			if err != nil {
				t.Errorf("Failed to init path: %s %s", "m", err.Error())
				return
			}

			bip32key, err := NewBip32Key(key, path)
			if !expected {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, bip32key)
			}
		})
	}
}

func TestInitRoot(t *testing.T) {
	params := &chaincfg.MainNetParams
	entropy := []byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}
	root, err := hdkeychain.NewMaster(entropy, params)
	assert.NoError(t, err)

	rootPub, err := root.Neuter()
	assert.NoError(t, err)

	child, err := root.Child(0)
	assert.NoError(t, err)

	fixtures := []struct {
		Key *hdkeychain.ExtendedKey
		Err error
	}{
		{
			Key: root,
			Err: nil,
		},
		{
			Key: rootPub,
			Err: nil,
		},
		{
			Key: child,
			Err: ErrBadRootKey,
		},
	}

	for i := 0; i < len(fixtures); i++ {
		fixture := fixtures[i]
		desc := fmt.Sprintf("depth(%d),parent(%d)", fixture.Key.Depth(), fixture.Key.ParentFingerprint())
		t.Run(desc, func(t *testing.T) {
			key, err := NewBip32MasterKey(fixture.Key)
			if fixture.Err != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, fixture.Err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestInit(t *testing.T) {
	params := &chaincfg.MainNetParams
	entropy := []byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}

	root, err := hdkeychain.NewMaster(entropy, params)
	assert.NoError(t, err)

	pathRootPriv := NewPrivatePath()
	pathRootPub := NewPublicPath()

	rootPub, err := root.Neuter()
	assert.NoError(t, err)

	child, err := root.Child(0)
	assert.NoError(t, err)

	childPub, err := child.Neuter()
	assert.NoError(t, err)

	childPathPriv, err := pathRootPriv.Child(0)
	assert.NoError(t, err)

	childPathPub, err := pathRootPub.Child(0)
	assert.NoError(t, err)

	fixtures := []struct {
		Key  *hdkeychain.ExtendedKey
		Path *Path
		Err  error
	}{
		{
			Key:  root,
			Path: pathRootPriv,
			Err:  nil,
		},
		{
			Key:  root,
			Path: pathRootPub,
			Err:  ErrKeyPathMismatch,
		},
		{
			Key:  rootPub,
			Path: pathRootPub,
			Err:  nil,
		},
		{
			Key:  rootPub,
			Path: pathRootPriv,
			Err:  ErrKeyPathMismatch,
		},
		{
			Key:  root,
			Path: childPathPriv,
			Err:  ErrKeyPathMismatch,
		},
		{
			Key:  child,
			Path: childPathPriv,
			Err:  nil,
		},
		{
			Key:  childPub,
			Path: childPathPub,
			Err:  nil,
		},
	}

	for i := 0; i < len(fixtures); i++ {
		fixture := fixtures[i]
		desc := fmt.Sprintf("depth(%d),parent(%d)", fixture.Key.Depth(), fixture.Key.ParentFingerprint())
		t.Run(desc, func(t *testing.T) {
			key, err := NewBip32Key(fixture.Key, fixture.Path)
			if fixture.Err != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, fixture.Err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}

func TestKeyFixturesToPublic(t *testing.T) {
	params := &chaincfg.MainNetParams
	entropy := []byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}

	root, err := hdkeychain.NewMaster(entropy, params)
	assert.NoError(t, err)

	rootPub, err := root.Neuter()
	assert.NoError(t, err)

	pathRootPriv := NewPrivatePath()
	pathRootPub := NewPublicPath()

	fixtures := []struct {
		Key  *hdkeychain.ExtendedKey
		Path *Path
		Err  error
	}{
		{
			Key:  root,
			Path: pathRootPriv,
			Err:  nil,
		},
		{
			Key:  rootPub,
			Path: pathRootPub,
			Err:  ErrKeyIsAlreadyPublic,
		},
	}

	for i := 0; i < len(fixtures); i++ {
		fixture := fixtures[i]
		description := fmt.Sprintf("to public %d", i)
		t.Run(description, func(t *testing.T) {
			key, err := NewBip32Key(fixture.Key, fixture.Path)
			assert.NoError(t, err)

			toPub, err := key.ToPublic()
			if fixture.Err != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, fixture.Err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, toPub)
			}
		})
	}
}

func TestChildFixtures(t *testing.T) {
	params := &chaincfg.MainNetParams
	entropy := []byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}

	root, err := hdkeychain.NewMaster(entropy, params)
	assert.NoError(t, err)

	rootPub, err := root.Neuter()
	assert.NoError(t, err)

	pathRootPriv := NewPrivatePath()
	pathRootPub := NewPublicPath()

	deriv255 := root
	p255 := NewPrivatePath()
	for i := 0; i < 255; i++ {
		var err error
		deriv255, err = deriv255.Child(0)
		assert.NoError(t, err)

		p255, err = p255.Child(0)
		assert.NoError(t, err)
	}

	fixtures := []struct {
		Key   *hdkeychain.ExtendedKey
		Path  *Path
		Child uint32
		Err   error
	}{
		{
			Key:   root,
			Path:  pathRootPriv,
			Child: 0,
			Err:   nil,
		},
		{
			Key:   rootPub,
			Path:  pathRootPub,
			Child: 0,
			Err:   nil,
		},
		{
			Key:   root,
			Path:  pathRootPriv,
			Child: 1,
			Err:   nil,
		},
		{
			Key:   root,
			Path:  pathRootPriv,
			Child: 0 + hdkeychain.HardenedKeyStart,
			Err:   nil,
		},
		{
			Key:   rootPub,
			Path:  pathRootPub,
			Child: 0 + hdkeychain.HardenedKeyStart,
			Err:   hdkeychain.ErrDeriveHardFromPublic,
		},
		{
			Key:   deriv255,
			Path:  p255,
			Child: 0,
			Err:   ErrPathAlreadyMaxDepth,
		},
	}

	for i := 0; i < len(fixtures); i++ {
		fixture := fixtures[i]
		description := fmt.Sprintf("to public %d", i)
		t.Run(description, func(t *testing.T) {
			key, err := NewBip32Key(fixture.Key, fixture.Path)
			if err != nil {
				t.Fatalf("abort test - key should init")
			}

			assert.NoError(t, err)

			child, err := key.Child(fixture.Child)
			if fixture.Err != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, fixture.Err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, child)

				lastIdx := child.Path.Depth() - 1
				assert.Equal(t, fixture.Child, child.Path.Path[lastIdx])
			}
		})
	}
}
