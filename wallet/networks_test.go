package wallet

import (
	"fmt"
	_assert "github.com/stretchr/testify/require"
	"testing"
)

func TestNetworks(t *testing.T) {
	_assert.Equal(t, "btc", NetBtc)
	_assert.Equal(t, "tbtc", NetBtcTest)
	_assert.Equal(t, "rbtc", NetBtcRegtest)

	_assert.Equal(t, "bch", NetBch)
	_assert.Equal(t, "tbch", NetBchTest)
	_assert.Equal(t, "rbch", NetBchRegtest)
}

func TestCheckNetwork(t *testing.T) {
	validNetworks := []string{
		NetBtc,
		NetBtcTest,
		NetBtcRegtest,
		NetBch,
		NetBchTest,
		NetBchRegtest,
	}

	for i := 0; i < len(validNetworks); i++ {
		network := validNetworks[i]
		t.Run(fmt.Sprintf("accepts %s", network), func(t *testing.T) {
			net, err := CheckNetwork(network)
			_assert.NoError(t, err)
			_assert.Equal(t, network, net)
		})
	}

	t.Run("rejects unknowns", func(t *testing.T) {
		_, err := CheckNetwork("unknown")
		_assert.Error(t, err)
		_assert.EqualError(t, err, "Network is invalid")
	})
}

func TestGetNetworkParams(t *testing.T) {
	fixtures := []struct {
		net    string
		params *Network
	}{
		{NetBtc, BtcNetwork},
		{NetBtcTest, BtcTestNetwork},
		{NetBtcRegtest, BtcRegtestNetwork},
		{NetBch, BchNetwork},
		{NetBchTest, BchTestNetwork},
		{NetBchRegtest, BchRegtestNetwork},
	}

	for i := 0; i < len(fixtures); i++ {
		t.Run(fixtures[i].net, func(t *testing.T) {
			net, err := GetNetworkParams(fixtures[i].net)
			_assert.NoError(t, err)
			_assert.Equal(t, fixtures[i].params, net)
		})
	}

	t.Run("rejects unknown networks", func(t *testing.T) {
		nn, err := GetNetworkParams("unknown")
		_assert.Nil(t, nn)
		_assert.Error(t, err)
		_assert.EqualError(t, err, "Invalid network")
	})
}
