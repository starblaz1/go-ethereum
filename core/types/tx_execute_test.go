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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

func TestExecuteTxCopyIsolated(t *testing.T) {
	orig := sampleExecuteTx()
	cpy, ok := orig.copy().(*ExecuteTx)
	if !ok {
		t.Fatalf("copy() returned unexpected type %T", cpy)
	}
	if !bytes.Equal(orig.Witness, cpy.Witness) || &orig.Witness[0] == &cpy.Witness[0] {
		t.Fatal("witness slice not copied deeply")
	}
	if !bytes.Equal(orig.Withdrawals, cpy.Withdrawals) || &orig.Withdrawals[0] == &cpy.Withdrawals[0] {
		t.Fatal("withdrawals slice not copied deeply")
	}
	if !bytes.Equal(orig.Data, cpy.Data) || (len(orig.Data) > 0 && &orig.Data[0] == &cpy.Data[0]) {
		t.Fatal("data slice not copied deeply")
	}
	if orig.BlobHashes[0] != cpy.BlobHashes[0] {
		t.Fatal("blob hashes not preserved")
	}
	if orig.To == nil || cpy.To == nil || *orig.To != *cpy.To {
		t.Fatal("to pointer value mismatch")
	}
	if orig.To == cpy.To {
		t.Fatal("to pointer not copied")
	}
	if orig.Value == nil || cpy.Value == nil || orig.Value.Cmp(cpy.Value) != 0 {
		t.Fatal("value mismatch after copy")
	}
	if orig.Value == cpy.Value {
		t.Fatal("value pointer not copied")
	}
	cpy.Witness[0] ^= 0xff
	if bytes.Equal(orig.Witness, cpy.Witness) {
		t.Fatal("mutating copy affected original witness")
	}
	cpy.Data[0] ^= 0xff
	if bytes.Equal(orig.Data, cpy.Data) {
		t.Fatal("mutating copy affected original data")
	}
}

func TestExecuteTxEncodeDecode(t *testing.T) {
	tx := sampleExecuteTx()
	var buf bytes.Buffer
	if err := tx.encode(&buf); err != nil {
		t.Fatalf("encode error: %v", err)
	}
	var decoded ExecuteTx
	if err := decoded.decode(buf.Bytes()); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if decoded.PreStateHash != tx.PreStateHash ||
		decoded.BlockNumber != tx.BlockNumber ||
		decoded.Timestamp != tx.Timestamp {
		t.Fatalf("decoded payload mismatch: %#v vs %#v", decoded, tx)
	}
	if decoded.To == nil || tx.To == nil || *decoded.To != *tx.To {
		t.Fatalf("decoded to mismatch: %#v vs %#v", decoded.To, tx.To)
	}
	if decoded.Value.Cmp(tx.Value) != 0 {
		t.Fatalf("decoded value mismatch: %v vs %v", decoded.Value, tx.Value)
	}
	if !bytes.Equal(decoded.Data, tx.Data) {
		t.Fatalf("data mismatch: %x vs %x", decoded.Data, tx.Data)
	}
	if !bytes.Equal(decoded.Witness, tx.Witness) {
		t.Fatalf("witness mismatch: %x vs %x", decoded.Witness, tx.Witness)
	}
	if !bytes.Equal(decoded.Withdrawals, tx.Withdrawals) {
		t.Fatalf("withdrawals mismatch")
	}
}

func TestExecuteTxDecodeWitnessSizeMismatch(t *testing.T) {
	rlpStruct := executeTxRLP{
		ChainID:         uint256.NewInt(1),
		Nonce:           7,
		GasTipCap:       uint256.NewInt(2),
		GasFeeCap:       uint256.NewInt(3),
		Gas:             25_000,
		PreStateHash:    common.HexToHash("0x01"),
		WitnessSize:     2,
		WithdrawalsSize: 1,
		Coinbase:        common.HexToAddress("0x1234"),
		BlockNumber:     11,
		Timestamp:       42,
		Witness:         []byte{0xaa},
		Withdrawals:     []byte{0xbb},
		BlobHashes:      []common.Hash{common.HexToHash("0x02")},
		V:               uint256.NewInt(1),
		R:               uint256.NewInt(2),
		S:               uint256.NewInt(3),
	}
	data, err := rlp.EncodeToBytes(&rlpStruct)
	if err != nil {
		t.Fatalf("rlp encode error: %v", err)
	}
	var decoded ExecuteTx
	if err := decoded.decode(data); err != errExecuteWitnessSizeMismatch {
		t.Fatalf("expected witness size mismatch error, got %v", err)
	}
}

func TestTransactionExecutePayloadDeepCopy(t *testing.T) {
	execTx := sampleExecuteTx()
	signed := NewTx(execTx)
	payload := signed.ExecutePayload()
	if payload == nil {
		t.Fatal("expected execute payload")
	}
	if payload.PreStateHash != execTx.PreStateHash {
		t.Fatal("prestate hash mismatch")
	}
	if payload.To == nil || execTx.To == nil || *payload.To != *execTx.To {
		t.Fatal("to mismatch")
	}
	if payload.To == execTx.To {
		t.Fatal("to pointer not copied")
	}
	if payload.Value.Cmp(execTx.Value.ToBig()) != 0 {
		t.Fatal("value mismatch")
	}
	payload.Witness[0] ^= 0xff
	if bytes.Equal(payload.Witness, execTx.Witness) {
		t.Fatal("payload witness not copied")
	}
	payload.Data[0] ^= 0xff
	if bytes.Equal(payload.Data, execTx.Data) {
		t.Fatal("payload data not copied")
	}
	payload.Value.Add(payload.Value, big.NewInt(1))
	if payload.Value.Cmp(execTx.Value.ToBig()) == 0 {
		t.Fatal("mutating payload value affected transaction")
	}
	if payload.BlobHashes[0] != execTx.BlobHashes[0] {
		t.Fatal("blob hashes mismatch")
	}
	if signed.ExecutePayload().Witness[0] != execTx.Witness[0] {
		t.Fatal("mutating payload affected transaction")
	}
}

func sampleExecuteTx() *ExecuteTx {
	to := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	return &ExecuteTx{
		ChainID:         uint256.NewInt(1),
		Nonce:           3,
		GasTipCap:       uint256.NewInt(1_000_000_000),
		GasFeeCap:       uint256.NewInt(2_000_000_000),
		Gas:             30_000,
		To:              &to,
		Value:           uint256.NewInt(12345),
		Data:            []byte{0xde, 0xad, 0xbe, 0xef},
		PreStateHash:    common.HexToHash("0x010203"),
		Witness:         []byte{0x01, 0x02, 0x03},
		Withdrawals:     []byte{0x04, 0x05},
		WitnessSize:     3,
		WithdrawalsSize: 2,
		Coinbase:        common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		BlockNumber:     128,
		Timestamp:       1_700_000_000,
		BlobHashes: []common.Hash{
			common.HexToHash("0x1111"),
		},
		V: uint256.NewInt(1),
		R: uint256.NewInt(2),
		S: uint256.NewInt(3),
	}
}
