// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software; you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation; either version 3 of the License, or (at your
// option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without express or implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
// General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package types implements EIP-6466 SSZ receipt hashing for the receipts_root
// when the SSZ receipts fork is active.
package types

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/common"
)

const (
	// SSZ receipt type tags per EIP-6466 CompatibleUnion
	sszBasicReceiptTag  = 0x01
	sszCreateReceiptTag = 0x02
	sszSetCodeReceiptTag = 0x03
	maxTopicsPerLog     = 4
)

// ReceiptsSSZRoot computes the EIP-6466 SSZ hash_tree_root of the receipts list.
// It requires the transactions to derive the sender (from) for each receipt and to
// distinguish Create vs Basic receipt type. signer is used to recover sender from tx.
func ReceiptsSSZRoot(receipts []*Receipt, txs []*Transaction, signer Signer) (common.Hash, error) {
	if len(receipts) != len(txs) {
		return common.Hash{}, errors.New("receipts and txs length mismatch")
	}
	if len(receipts) == 0 {
		root := mixInLength([32]byte{}, 0)
		return root, nil
	}
	roots := make([][32]byte, len(receipts))
	for i := range receipts {
		from, err := Sender(signer, txs[i])
		if err != nil {
			return common.Hash{}, err
		}
		r, err := receiptSSZRoot(receipts[i], txs[i], from)
		if err != nil {
			return common.Hash{}, err
		}
		roots[i] = r
	}
	return merkleizeList(roots)
}

// receiptSSZRoot returns the SSZ hash_tree_root of a single receipt (CompatibleUnion).
func receiptSSZRoot(r *Receipt, tx *Transaction, from common.Address) ([32]byte, error) {
	var inner [32]byte
	switch r.Type {
	case LegacyTxType, AccessListTxType, DynamicFeeTxType, BlobTxType, ExecuteTxType:
		if tx.To() == nil {
			var err error
			inner, err = createReceiptSSZRoot(from, r.GasUsed, r.ContractAddress, r.Logs, r.Status == ReceiptStatusSuccessful)
			if err != nil {
				return [32]byte{}, err
			}
			return unionRoot(sszCreateReceiptTag, inner)
		}
		inner2, err := basicReceiptSSZRoot(from, r.GasUsed, r.Logs, r.Status == ReceiptStatusSuccessful)
		if err != nil {
			return [32]byte{}, err
		}
		return unionRoot(sszBasicReceiptTag, inner2)
	case SetCodeTxType:
		// Authorities: empty for now; EIP-7702 execution would populate.
		inner2, err := setCodeReceiptSSZRoot(from, r.GasUsed, r.Logs, r.Status == ReceiptStatusSuccessful, nil)
		if err != nil {
			return [32]byte{}, err
		}
		return unionRoot(sszSetCodeReceiptTag, inner2)
	default:
		// Fallback to BasicReceipt for unknown types (e.g. future)
		inner2, err := basicReceiptSSZRoot(from, r.GasUsed, r.Logs, r.Status == ReceiptStatusSuccessful)
		if err != nil {
			return [32]byte{}, err
		}
		return unionRoot(sszBasicReceiptTag, inner2)
	}
}

func unionRoot(tag byte, inner [32]byte) ([32]byte, error) {
	// CompatibleUnion: root = H(tag || inner_root)
	buf := make([]byte, 33)
	buf[0] = tag
	copy(buf[1:], inner[:])
	return hashToRoot(buf), nil
}

func basicReceiptSSZRoot(from common.Address, gasUsed uint64, logs []*Log, status bool) ([32]byte, error) {
	logsRoot, err := logsSSZRoot(logs)
	if err != nil {
		return [32]byte{}, err
	}
	// BasicReceipt: from_, gas_used, logs, status (active_fields [1,1,0,1,1] - all present)
	return merkleizeChunks([][]byte{
		addressToChunk(from),
		uint64ToChunk(gasUsed),
		logsRoot[:],
		boolToChunk(status),
	}), nil
}

func createReceiptSSZRoot(from common.Address, gasUsed uint64, contract common.Address, logs []*Log, status bool) ([32]byte, error) {
	logsRoot, err := logsSSZRoot(logs)
	if err != nil {
		return [32]byte{}, err
	}
	return merkleizeChunks([][]byte{
		addressToChunk(from),
		uint64ToChunk(gasUsed),
		addressToChunk(contract),
		logsRoot[:],
		boolToChunk(status),
	}), nil
}

func setCodeReceiptSSZRoot(from common.Address, gasUsed uint64, logs []*Log, status bool, authorities []common.Address) ([32]byte, error) {
	logsRoot, err := logsSSZRoot(logs)
	if err != nil {
		return [32]byte{}, err
	}
	authRoot, err := authoritiesSSZRoot(authorities)
	if err != nil {
		return [32]byte{}, err
	}
	return merkleizeChunks([][]byte{
		addressToChunk(from),
		uint64ToChunk(gasUsed),
		logsRoot[:],
		boolToChunk(status),
		authRoot[:],
	}), nil
}

func logsSSZRoot(logs []*Log) ([32]byte, error) {
	if len(logs) == 0 {
		return merkleizeList(nil)
	}
	roots := make([][32]byte, len(logs))
	for i, l := range logs {
		r, err := logSSZRoot(l)
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = r
	}
	return merkleizeList(roots)
}

// logSSZRoot hashes a Log per EIP-6466: address (Bytes20), topics (List[Bytes32, 4]), data (ProgressiveByteList).
func logSSZRoot(l *Log) ([32]byte, error) {
	topics := make([][]byte, maxTopicsPerLog)
	for i := 0; i < maxTopicsPerLog; i++ {
		if i < len(l.Topics) {
			topics[i] = l.Topics[i][:]
		} else {
			topics[i] = make([]byte, 32)
		}
	}
	topicsRoot := merkleizeChunks(topics)
	dataRoot := bytesToRoot(l.Data)
	return merkleizeChunks([][]byte{
		addressToChunk(l.Address),
		topicsRoot[:],
		dataRoot[:],
	}), nil
}

func authoritiesSSZRoot(addrs []common.Address) ([32]byte, error) {
	if len(addrs) == 0 {
		return mixInLength([32]byte{}, 0), nil
	}
	chunks := make([][]byte, len(addrs))
	for i := range addrs {
		chunks[i] = addressToChunk(addrs[i])
	}
	root := merkleizeChunks(chunks)
	return mixInLength(root, uint64(len(addrs))), nil
}

// SSZ helpers: little-endian, 32-byte chunks, SHA256 Merkleization

func addressToChunk(a common.Address) []byte {
	chunk := make([]byte, 32)
	copy(chunk[12:32], a[:]) // right-align 20 bytes
	return chunk
}

func uint64ToChunk(v uint64) []byte {
	chunk := make([]byte, 32)
	binary.LittleEndian.PutUint64(chunk[0:8], v)
	return chunk
}

func boolToChunk(b bool) []byte {
	chunk := make([]byte, 32)
	if b {
		chunk[0] = 1
	}
	return chunk
}

func bytesToRoot(b []byte) [32]byte {
	if len(b) == 0 {
		return merkleizeChunks(nil)
	}
	chunks := make([][]byte, (len(b)+31)/32)
	for i := range chunks {
		start := i * 32
		end := start + 32
		if end > len(b) {
			end = len(b)
		}
		chunk := make([]byte, 32)
		copy(chunk, b[start:end])
		chunks[i] = chunk
	}
	return merkleizeWithMixin(chunks, uint64(len(b)))
}

func hashToRoot(b []byte) [32]byte {
	h := sha256.Sum256(b)
	return h
}

// merkleizeChunks returns the Merkle root of the chunks (padded to power of 2).
func merkleizeChunks(chunks [][]byte) [32]byte {
	if len(chunks) == 0 {
		return [32]byte{}
	}
	// Pad to next power of 2
	size := nextPowerOfTwo(len(chunks))
	leaves := make([][32]byte, size)
	for i := range leaves {
		if i < len(chunks) {
			copy(leaves[i][:], chunks[i])
		}
	}
	return merkleize(leaves)
}

// merkleizeList returns hash_tree_root of a list: mix_in_length(merkleize(roots), len).
func merkleizeList(roots [][32]byte) ([32]byte, error) {
	if len(roots) == 0 {
		return mixInLength([32]byte{}, 0), nil
	}
	chunks := make([][]byte, len(roots))
	for i := range roots {
		chunks[i] = roots[i][:]
	}
	root := merkleizeChunks(chunks)
	return mixInLength(root, uint64(len(roots))), nil
}

func mixInLength(root [32]byte, length uint64) [32]byte {
	lenBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lenBuf[0:8], length)
	return hashToRoot(append(root[:], lenBuf...))
}

func merkleizeWithMixin(chunks [][]byte, length uint64) [32]byte {
	size := nextPowerOfTwo(len(chunks))
	leaves := make([][32]byte, size)
	for i := range leaves {
		if i < len(chunks) {
			copy(leaves[i][:], chunks[i])
		}
	}
	root := merkleize(leaves)
	return mixInLength(root, length)
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

func merkleize(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	next := make([][32]byte, (len(leaves)+1)/2)
	for i := 0; i < len(next); i++ {
		left := leaves[2*i]
		var right [32]byte
		if 2*i+1 < len(leaves) {
			right = leaves[2*i+1]
		}
		next[i] = hashToRoot(append(left[:], right[:]...))
	}
	return merkleize(next)
}
