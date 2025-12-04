package merkletree

import (
	"bytes"
	"fmt"
	"sort"

	"golang.org/x/crypto/sha3"
)

// LeafHash represents a function that computes the hash of a leaf.
type LeafHash[T any] func(leaf T) HexString

// NodeHash represents a function that computes the hash of a node from two children.
type NodeHash func(left BytesLike, right BytesLike) HexString

// StandardLeafHash computes the standard hash of a leaf using Keccak256,
// compatible with OpenZeppelin's Merkle tree implementation.
// It uses ABI encoding similar to Ethereum's encodePacked.
func StandardLeafHash[T any](value T) HexString {
	encodedPacked, err := keccak256HashedData(value)
	if err != nil {
		// In case of error, return empty hash
		// This shouldn't happen with valid input types
		return HexString("")
	}
	encodedPackedHex, err := ToHex(encodedPacked)
	if err != nil {
		return HexString("")
	}
	return encodedPackedHex
}

// StandardNodeHash computes the standard hash of two child nodes.
// It sorts the nodes lexicographically before hashing to ensure consistency
// regardless of the order they are provided (this is important for proof verification).
// Compatible with OpenZeppelin's Merkle tree implementation.
func StandardNodeHash(a BytesLike, b BytesLike) HexString {
	// Sort the two nodes to ensure consistency
	nodes := []BytesLike{a, b}
	sort.Slice(nodes, func(i, j int) bool {
		result, err := Compare(nodes[i], nodes[j])
		if err != nil {
			return false
		}
		return result < 0
	})

	concatenated, err := Concat(nodes[0], nodes[1])
	if err != nil {
		return HexString("")
	}

	hashed, err := keccak256HashedData(concatenated)
	if err != nil {
		return HexString("")
	}

	hashedHex, err := ToHex(hashed)
	if err != nil {
		return HexString("")
	}

	return hashedHex
}

// abiEncodePacked encodes arguments in a packed format similar to Solidity's abi.encodePacked.
// It concatenates values without padding, which is different from standard ABI encoding.
func abiEncodePacked(args ...interface{}) ([]byte, error) {
	var buf bytes.Buffer

	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			buf.Write([]byte(v)) // Convert string to bytes without padding
		case []byte:
			buf.Write(v) // Write bytes directly
		case uint8, uint16, uint32, uint64, int8, int16, int32, int64:
			buf.Write(uintToBytes(v)) // Convert integers to bytes
		default:
			return nil, fmt.Errorf("unsupported type in abiEncodePacked: %T", v)
		}
	}

	return buf.Bytes(), nil
}

// uintToBytes converts integer types to byte arrays without extra padding.
// Uses big-endian byte order (most significant byte first).
func uintToBytes(num interface{}) []byte {
	switch v := num.(type) {
	case uint8:
		return []byte{v}
	case uint16:
		return []byte{byte(v >> 8), byte(v)}
	case uint32:
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	case uint64:
		return []byte{
			byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
		}
	case int8:
		return []byte{byte(v)}
	case int16:
		return []byte{byte(v >> 8), byte(v)}
	case int32:
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	case int64:
		return []byte{
			byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
		}
	default:
		return nil
	}
}

// keccak256HashedData encodes the arguments using abiEncodePacked and then
// computes the Keccak256 hash (Ethereum's version of SHA3).
func keccak256HashedData(args ...interface{}) ([]byte, error) {
	encodedData, err := abiEncodePacked(args...)
	if err != nil {
		return nil, err
	}

	// Compute Keccak256 (Ethereum-specific SHA3)
	hash := sha3.NewLegacyKeccak256()
	hash.Write(encodedData)
	return hash.Sum(nil), nil
}
