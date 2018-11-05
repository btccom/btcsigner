package bip32util

import (
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/pkg/errors"
	"math"
	"strconv"
	"strings"
)

var (
	// ErrPathMissingKeyIndex is thrown when a
	// path is too short, and doesn't include the
	// key index field
	ErrPathMissingKeyIndex = errors.New("No key index set on Bip32Path")

	// ErrPathAlreadyMaxDepth is returned when the
	// BIP32 key has reached it's theoretical maximum
	// depth of 255, since additional derivations cannot
	// safely be serialized in a uint8
	ErrPathAlreadyMaxDepth = errors.New("Cannot create child path, currently at max BIP32 depth")
)

const (
	privatePathPrefix = "m"
	publicPathPrefix  = "M"
	privatePathSymbol = "'"
	maxBip32Depth     = math.MaxUint8
)

// NewPathFromString wraps a call to PathInfoFromString, and initializes
// a Path from the result.
func NewPathFromString(path string) (*Path, error) {
	var err error
	p := &Path{}
	p.fPriv, p.Path, err = PathInfoFromString(path)

	if err != nil {
		return nil, err
	}

	return p, nil
}

// Path defines a BIP32 derivation path out of
// primitive information like
type Path struct {
	fPriv bool
	Path  []uint32
}

// NewPrivatePath initializes a path for `m`
func NewPrivatePath() *Path {
	return &Path{
		fPriv: true,
		Path:  make([]uint32, 0),
	}
}

// NewPublicPath initializes a path for `M`
func NewPublicPath() *Path {
	return &Path{
		fPriv: false,
		Path:  make([]uint32, 0),
	}
}

// Child attempts to append another sequence
// number to the path array, returning a new
// structure
func (p *Path) Child(sequence uint32) (*Path, error) {
	newDepth := p.Depth() + 1
	if newDepth > maxBip32Depth {
		return nil, ErrPathAlreadyMaxDepth
	}

	indices := p.Path
	indices = append(indices, sequence)

	newPath := &Path{}
	newPath.Path = indices
	newPath.fPriv = p.fPriv

	return newPath, nil
}

// ToPublic returns a new struct with the same
// info, except fPriv is now false
func (p *Path) ToPublic() *Path {
	newPath := &Path{}
	newPath.Path = p.Path
	newPath.fPriv = false

	return newPath
}

// ToPrivate returns a new struct with the same
// info, except fPriv is now true
func (p *Path) ToPrivate() *Path {
	newPath := &Path{}
	newPath.Path = p.Path
	newPath.fPriv = true

	return newPath
}

// Depth returns the current depth of the path
func (p *Path) Depth() int {
	return len(p.Path)
}

// IsPrivate returns whether the path is for a
// public (false) or private (true) key.
func (p *Path) IsPrivate() bool {
	return p.fPriv
}

// GetKeyIndex returns the key index field if
// it exists in the path.
func (p *Path) GetKeyIndex() (uint32, error) {
	if p.Depth() < 1 {
		return 0, ErrPathMissingKeyIndex
	}

	return p.Path[0] - hdkeychain.HardenedKeyStart, nil
}

// IsContainedIn checks that the current p is completely
// specified in the other Path.
func (p *Path) IsContainedIn(other *Path) bool {
	depth := p.Depth()
	// This p must be FULLY contained inside other.Path
	if depth > other.Depth() {
		return false
	}

	for i := 0; i < depth; i++ {
		if !(p.Path[i] == other.Path[i]) {
			return false
		}
	}

	return true
}

// isBip32SequenceHardened returns whether the provided
// sequence has the leftmost bit set.
func isBip32SequenceHardened(sequence uint32) bool {
	return sequence&hdkeychain.HardenedKeyStart != 0
}

// PathSegmentFromSequence is used for serializing the
// sequence parameter from a Path into a string. The
// function returns the sequence number as a string, with
// the private path symbol if the sequence is hardened.
func PathSegmentFromSequence(sequence uint32) string {
	isHardened := isBip32SequenceHardened(sequence)
	if isHardened {
		return strconv.Itoa(int(sequence-hdkeychain.HardenedKeyStart)) + privatePathSymbol
	}
	return strconv.Itoa(int(sequence))
}

// PathInfoFromString is used by other code, it takes
// a path(string) and extracts fPriv, Path, or an error.
func PathInfoFromString(path string) (bool, []uint32, error) {
	strLen := len(path)
	if strLen == 0 {
		return false, nil, errors.New("Path cannot be empty string")
	}

	var isPrivateKey bool
	if strings.HasPrefix(path, privatePathPrefix) {
		isPrivateKey = true
	} else if strings.HasPrefix(path, publicPathPrefix) {
		isPrivateKey = false
	} else {
		return false, nil, errors.New("Absolute BIP32 path is required")
	}

	pieces := strings.Split(path, "/")
	_, pieces = pieces[0], pieces[1:]

	depth := len(pieces)
	if depth > maxBip32Depth {
		return false, nil, errors.Errorf("The provided path exceeds the maximum number of allowed derivations: %d", math.MaxUint8)
	}

	indices := make([]uint32, depth)
	for i := 0; i < depth; i++ {
		segment := pieces[i]
		numHardened := strings.Count(segment, "'")

		var hardened bool
		if numHardened > 1 {
			return false, nil, errors.Errorf("Improperly formatted BIP32 derivation (cannot contain multiple ' characters)")
		} else if numHardened > 0 {
			hardened = true
			segment = strings.Replace(segment, privatePathSymbol, "", 1)
		} else {
			hardened = false
		}

		sequence, err := strconv.ParseUint(segment, 10, 31)
		if err != nil {
			return false, nil, err
		}

		if hardened {
			sequence = sequence + hdkeychain.HardenedKeyStart
		}

		indices[i] = uint32(sequence)
	}

	return isPrivateKey, indices, nil
}

// String encodes the Path structure into a string that
// is human readable, eg, M/9999'/0/1
func (p *Path) String() string {
	steps := make([]string, 1+p.Depth())
	if p.fPriv {
		steps[0] = privatePathPrefix
	} else {
		steps[0] = publicPathPrefix
	}

	for i := 0; i < p.Depth(); i++ {
		steps[1+i] = PathSegmentFromSequence(p.Path[i])
	}

	return strings.Join(steps, "/")
}
