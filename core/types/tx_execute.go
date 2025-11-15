// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

var (
	errExecuteWitnessSizeMismatch     = errors.New("execute tx witness size mismatch")
	errExecuteWithdrawalsSizeMismatch = errors.New("execute tx withdrawals size mismatch")
)

// ExecuteTx represents the typed transaction that targets the EXECUTE precompile.
type ExecuteTx struct {
	ChainID *uint256.Int
	Nonce   uint64

	GasTipCap *uint256.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap *uint256.Int // a.k.a. maxFeePerGas
	Gas       uint64

	To    *common.Address `rlp:"nil"`
	Value *uint256.Int
	Data  []byte

	PreStateHash    common.Hash
	WitnessSize     uint32
	WithdrawalsSize uint32
	Coinbase        common.Address
	BlockNumber     uint64
	Timestamp       uint64
	Witness         []byte
	Withdrawals     []byte
	BlobHashes      []common.Hash

	// Signature values
	V *uint256.Int
	R *uint256.Int
	S *uint256.Int
}

type executeTxRLP struct {
	ChainID         *uint256.Int
	Nonce           uint64
	GasTipCap       *uint256.Int
	GasFeeCap       *uint256.Int
	Gas             uint64
	To              *common.Address `rlp:"nil"`
	Value           *uint256.Int
	Data            []byte
	PreStateHash    common.Hash
	WitnessSize     uint64
	WithdrawalsSize uint64
	Coinbase        common.Address
	BlockNumber     uint64
	Timestamp       uint64
	Witness         []byte
	Withdrawals     []byte
	BlobHashes      []common.Hash
	V               *uint256.Int
	R               *uint256.Int
	S               *uint256.Int
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *ExecuteTx) copy() TxData {
	cpy := &ExecuteTx{
		Nonce:           tx.Nonce,
		Gas:             tx.Gas,
		To:              copyAddressPtr(tx.To),
		Data:            common.CopyBytes(tx.Data),
		PreStateHash:    tx.PreStateHash,
		WitnessSize:     tx.WitnessSize,
		WithdrawalsSize: tx.WithdrawalsSize,
		Coinbase:        tx.Coinbase,
		BlockNumber:     tx.BlockNumber,
		Timestamp:       tx.Timestamp,
		Witness:         common.CopyBytes(tx.Witness),
		Withdrawals:     common.CopyBytes(tx.Withdrawals),
		BlobHashes:      make([]common.Hash, len(tx.BlobHashes)),
		Value:           new(uint256.Int),
		ChainID:         new(uint256.Int),
		GasTipCap:       new(uint256.Int),
		GasFeeCap:       new(uint256.Int),
		V:               new(uint256.Int),
		R:               new(uint256.Int),
		S:               new(uint256.Int),
	}
	copy(cpy.BlobHashes, tx.BlobHashes)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// accessors for innerTx.
func (tx *ExecuteTx) txType() byte           { return ExecuteTxType }
func (tx *ExecuteTx) chainID() *big.Int      { return tx.ChainID.ToBig() }
func (tx *ExecuteTx) accessList() AccessList { return nil }
func (tx *ExecuteTx) data() []byte           { return tx.Data }
func (tx *ExecuteTx) gas() uint64            { return tx.Gas }
func (tx *ExecuteTx) gasFeeCap() *big.Int    { return tx.GasFeeCap.ToBig() }
func (tx *ExecuteTx) gasTipCap() *big.Int    { return tx.GasTipCap.ToBig() }
func (tx *ExecuteTx) gasPrice() *big.Int     { return tx.GasFeeCap.ToBig() }
func (tx *ExecuteTx) value() *big.Int {
	if tx.Value == nil {
		return new(big.Int)
	}
	return tx.Value.ToBig()
}
func (tx *ExecuteTx) nonce() uint64 { return tx.Nonce }

func (tx *ExecuteTx) to() *common.Address {
	if tx.To != nil {
		return copyAddressPtr(tx.To)
	}
	addr := params.ExecutePrecompileAddress
	return &addr
}

func (tx *ExecuteTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := dst.Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return tip.Add(tip, baseFee)
}

func (tx *ExecuteTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V.ToBig(), tx.R.ToBig(), tx.S.ToBig()
}

func (tx *ExecuteTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = uint256.MustFromBig(chainID)
	tx.V = uint256.MustFromBig(v)
	tx.R = uint256.MustFromBig(r)
	tx.S = uint256.MustFromBig(s)
}

func (tx *ExecuteTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, &executeTxRLP{
		ChainID:         tx.ChainID,
		Nonce:           tx.Nonce,
		GasTipCap:       tx.GasTipCap,
		GasFeeCap:       tx.GasFeeCap,
		Gas:             tx.Gas,
		To:              tx.To,
		Value:           ensureUint256(tx.Value),
		Data:            tx.Data,
		PreStateHash:    tx.PreStateHash,
		WitnessSize:     uint64(tx.WitnessSize),
		WithdrawalsSize: uint64(tx.WithdrawalsSize),
		Coinbase:        tx.Coinbase,
		BlockNumber:     tx.BlockNumber,
		Timestamp:       tx.Timestamp,
		Witness:         tx.Witness,
		Withdrawals:     tx.Withdrawals,
		BlobHashes:      tx.BlobHashes,
		V:               tx.V,
		R:               tx.R,
		S:               tx.S,
	})
}

func (tx *ExecuteTx) decode(input []byte) error {
	var dec executeTxRLP
	if err := rlp.DecodeBytes(input, &dec); err != nil {
		return err
	}
	tx.ChainID = ensureUint256(dec.ChainID)
	tx.Nonce = dec.Nonce
	tx.GasTipCap = ensureUint256(dec.GasTipCap)
	tx.GasFeeCap = ensureUint256(dec.GasFeeCap)
	tx.Gas = dec.Gas
	tx.To = copyAddressPtr(dec.To)
	tx.Value = ensureUint256(dec.Value)
	tx.Data = dec.Data
	tx.PreStateHash = dec.PreStateHash
	tx.WitnessSize = uint32(dec.WitnessSize)
	tx.WithdrawalsSize = uint32(dec.WithdrawalsSize)
	tx.Coinbase = dec.Coinbase
	tx.BlockNumber = dec.BlockNumber
	tx.Timestamp = dec.Timestamp
	tx.Witness = dec.Witness
	tx.Withdrawals = dec.Withdrawals
	tx.BlobHashes = dec.BlobHashes
	tx.V = ensureUint256(dec.V)
	tx.R = ensureUint256(dec.R)
	tx.S = ensureUint256(dec.S)

	if uint64(len(tx.Witness)) != uint64(tx.WitnessSize) {
		return errExecuteWitnessSizeMismatch
	}
	if uint64(len(tx.Withdrawals)) != uint64(tx.WithdrawalsSize) {
		return errExecuteWithdrawalsSizeMismatch
	}
	return nil
}

func (tx *ExecuteTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		ExecuteTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			tx.PreStateHash,
			tx.WitnessSize,
			tx.WithdrawalsSize,
			tx.Coinbase,
			tx.BlockNumber,
			tx.Timestamp,
			tx.Witness,
			tx.Withdrawals,
			tx.BlobHashes,
		},
	)
}

func ensureUint256(v *uint256.Int) *uint256.Int {
	if v == nil {
		return new(uint256.Int)
	}
	return v
}
