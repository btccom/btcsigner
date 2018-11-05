package bip32util

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewPublicPath(t *testing.T) {
	path := NewPublicPath()
	assert.Equal(t, false, path.fPriv)
	assert.Equal(t, 0, path.Depth())
	assert.Equal(t, 0, len(path.Path))
}
func TestNewPrivatePath(t *testing.T) {
	path := NewPrivatePath()
	assert.Equal(t, true, path.fPriv)
	assert.Equal(t, 0, path.Depth())
	assert.Equal(t, 0, len(path.Path))
}

type bip32PathTestCase struct {
	path    string
	private bool
	depth   int
}

func TestBip32Path_FromString(t *testing.T) {
	tests := []bip32PathTestCase{
		// Private root path
		{"m", true, 0},
		{"M", false, 0},
		{"m/0", true, 1},
		{"M/0", false, 1},
		{"m/0'", true, 1},
		{"M/0'", false, 1},
		{"m/1/2'/3/4'/5'/6/7/8'/9'/10", true, 10},
		{"M/1'/2'/3/4'/5'/6/7/8'/9'/10'", false, 10},

		{"m/2147483647'", true, 1},
	}

	for _, test := range tests {

		isPrv, indices, err := PathInfoFromString(test.path)

		assert.NoError(t, err)
		assert.Equal(t, test.private, isPrv)
		assert.Equal(t, test.depth, len(indices))

		b32path, err := NewPathFromString(test.path)

		assert.NoError(t, err)
		assert.Equal(t, test.private, b32path.fPriv)
		assert.Equal(t, test.depth, b32path.Depth())

		returned := b32path.String()
		assert.Equal(t, test.path, returned)
	}
}

type bip32PathTestError struct {
	path  string
	error string
}

func TestBip32Path_ErrorFromString(t *testing.T) {
	tests := []bip32PathTestError{
		{"", "Path cannot be empty string"},
		{"G/0", "Absolute BIP32 path is required"},
		{"0", "Absolute BIP32 path is required"},
		{"m/0''", "Improperly formatted BIP32 derivation (cannot contain multiple ' characters)"},
		{"m/2147483648'", `strconv.ParseUint: parsing "2147483648": value out of range`},
		{"m/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4/1/2/3/4", "The provided path exceeds the maximum number of allowed derivations: 255"},
	}

	for _, test := range tests {
		_, _, err := PathInfoFromString(test.path)
		assert.Error(t, err)
		assert.Equal(t, test.error, err.Error())

		path, err := NewPathFromString(test.path)
		assert.Error(t, err)
		assert.Nil(t, path)
		assert.Equal(t, test.error, err.Error())
	}
}
