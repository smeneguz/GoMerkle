package merkletree

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// BytesLike represents types compatible with hashing operations.
// It can be a byte array, hex string, or other convertible types.
type BytesLike interface{}

// HexString represents a hexadecimal string with "0x" prefix.
type HexString string

// ToBytes converts a BytesLike value to a byte array.
// Supports: []byte, HexString, string (with or without "0x" prefix), and []int.
// Returns an error if the type is not supported or conversion fails.
func ToBytes(value BytesLike) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case HexString:
		// Recursively convert HexString to string and then to bytes
		return ToBytes(string(v))
	case string:
		if strings.HasPrefix(v, "0x") {
			hexData := v[2:] // Remove "0x" prefix
			decoded, err := hex.DecodeString(hexData)
			if err != nil {
				return nil, fmt.Errorf("invalid hex string: %w", err)
			}
			return decoded, nil
		}
		return []byte(v), nil
	case []int:
		bytes := make([]byte, len(v))
		for i, num := range v {
			bytes[i] = byte(num)
		}
		return bytes, nil
	default:
		return nil, errors.New("unsupported type in ToBytes")
	}
}

// ToHex converts a BytesLike value to a HexString with "0x" prefix.
// Supports: string, HexString, []byte, and []int.
// Returns an error if the type is not supported or conversion fails.
func ToHex(value BytesLike) (HexString, error) {
	switch v := value.(type) {
	case string, HexString:
		str := fmt.Sprintf("%v", v)
		// Validate that it's a valid hex string
		_, err := hex.DecodeString(strings.TrimPrefix(str, "0x"))
		if err != nil {
			return "", fmt.Errorf("invalid hex string: %w", err)
		}
		return HexString("0x" + strings.TrimPrefix(str, "0x")), nil
	case []byte:
		return HexString("0x" + hex.EncodeToString(v)), nil
	case []int:
		bytes, err := ToBytes(v)
		if err != nil {
			return "", err
		}
		return HexString("0x" + hex.EncodeToString(bytes)), nil
	default:
		return "", errors.New("unsupported type in ToHex")
	}
}

// Concat concatenates multiple BytesLike values into a single byte array.
// Returns an error if any value cannot be converted to bytes.
func Concat(values ...BytesLike) ([]byte, error) {
	var result []byte
	for _, v := range values {
		bytes, err := ToBytes(v)
		if err != nil {
			return nil, err
		}
		result = append(result, bytes...)
	}
	return result, nil
}

// Compare compares two BytesLike values lexicographically as big integers.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Returns an error if conversion to hex fails.
func Compare(a BytesLike, b BytesLike) (int, error) {
	aHex, err := ToHex(a)
	if err != nil {
		return 0, err
	}
	bHex, err := ToHex(b)
	if err != nil {
		return 0, err
	}

	aBigInt := new(big.Int)
	bBigInt := new(big.Int)

	// Remove "0x" prefix and convert to BigInt
	aBigInt.SetString(string(aHex)[2:], 16)
	bBigInt.SetString(string(bHex)[2:], 16)

	return aBigInt.Cmp(bBigInt), nil
}
