package fox

import (
	"crypto/ed25519"
	"encoding/hex"
	"github.com/spacemeshos/go-spacemesh/common/types"
	"github.com/spacemeshos/go-spacemesh/genvm/sdk"
	"github.com/spacemeshos/go-spacemesh/genvm/sdk/wallet"
	"strconv"
)

func SpaceMeshAddressFromPubKey(pubHex string) string {
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return Err(err)
	}
	return Ok(wallet.Address(pub).String())
}

func SpaceMeshStringToAddress(address string) string {
	toAddr, err := types.StringToAddress(address)
	if err != nil {
		return Err(err)
	}
	if toAddr.IsEmpty() {
		return Ok("")
	}
	return Ok(toAddr.String())
}

func SpaceMeshCreateTransaction(pk string, to string, amountStr string, nonceStr string, gasPriceStr string, genesisID string) string {
	priv, err := hex.DecodeString(pk)
	if err != nil {
		return Err(err)
	}
	privKey := ed25519.NewKeyFromSeed(priv)
	toAddr, err := types.StringToAddress(to)
	if err != nil {
		return Err(err)
	}
	var opts []sdk.Opt
	if len(gasPriceStr) > 0 {
		gasPrice, err := strconv.ParseUint(gasPriceStr, 10, 64)
		if err != nil {
			return Err(err)
		}
		opts = append(opts, sdk.WithGasPrice(gasPrice))
	}
	if len(genesisID) > 0 {
		genesisBytes, err := hex.DecodeString(genesisID)
		if err != nil {
			return Err(err)
		}
		var genesis types.Hash20
		copy(genesis[:], genesisBytes)
		opts = append(opts, sdk.WithGenesisID(genesis))
	}
	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		return Err(err)
	}
	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return Err(err)
	}
	tx := wallet.Spend(privKey, toAddr, amount, nonce, opts...)
	return Ok(hex.EncodeToString(tx))
}

func SpaceMeshSelfSpawnTx(pk string, nonceStr string, gasPriceStr string, genesisID string) string {
	priv, err := hex.DecodeString(pk)
	if err != nil {
		return Err(err)
	}
	privKey := ed25519.NewKeyFromSeed(priv)
	var opts []sdk.Opt
	if len(gasPriceStr) > 0 {
		gasPrice, err := strconv.ParseUint(gasPriceStr, 10, 64)
		if err != nil {
			return Err(err)
		}
		opts = append(opts, sdk.WithGasPrice(gasPrice))
	}
	if len(genesisID) > 0 {
		genesisBytes, err := hex.DecodeString(genesisID)
		if err != nil {
			return Err(err)
		}
		var genesis types.Hash20
		copy(genesis[:], genesisBytes)
		opts = append(opts, sdk.WithGenesisID(genesis))
	}
	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return Err(err)
	}
	tx := wallet.SelfSpawn(privKey, nonce, opts...)
	return Ok(hex.EncodeToString(tx))
}
