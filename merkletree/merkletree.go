package merkletree

import (
	"fmt"
)

// MerkleTreeImpl is the base structure for a Merkle tree.
// It uses Go generics to support any value type T.
type MerkleTreeImpl[T any] struct {
	Tree   []HexString // Flat array representation of the tree
	Values []struct {  // Values with their positions in the tree
		Value     T
		TreeIndex int
	}
	LeafHash   func(T) HexString // Function to hash leaves
	NodeHash   NodeHash          // Function to hash internal nodes
	HashLookup map[HexString]int // Maps leaf hashes to value indices
}

// Root returns the root hash of the Merkle tree.
func (m *MerkleTreeImpl[T]) Root() HexString {
	if len(m.Tree) == 0 {
		return HexString("")
	}
	return m.Tree[0]
}

// getLeafIndex returns the index of a value in the Merkle tree.
// The leaf parameter can be either an integer index or a value of type T.
// Returns an error if the index is out of bounds or the value is not found.
func (m *MerkleTreeImpl[T]) getLeafIndex(leaf any) (int, error) {
	switch v := leaf.(type) {
	case int:
		if v < 0 || v >= len(m.Values) {
			return -1, fmt.Errorf("%w: leaf index %d (max: %d)", ErrInvalidIndex, v, len(m.Values)-1)
		}
		return v, nil
	default:
		hashedLeaf := m.LeafHash(v.(T))
		if index, found := m.HashLookup[hashedLeaf]; found {
			return index, nil
		}
		return -1, ErrValueNotFound
	}
}

// validateValueAt verifies that the value at the given index is valid in the Merkle tree.
// Returns an error if the index is out of bounds or the hash doesn't match.
func (m *MerkleTreeImpl[T]) validateValueAt(index int) error {
	if index < 0 || index >= len(m.Values) {
		return fmt.Errorf("%w: index %d (max: %d)", ErrInvalidIndex, index, len(m.Values)-1)
	}

	expectedHash := m.LeafHash(m.Values[index].Value)
	actualHash := m.Tree[m.Values[index].TreeIndex]

	if expectedHash != actualHash {
		return fmt.Errorf("value mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

// IsValidMerkleTree verifies if a Merkle tree is structurally valid.
// It checks that each internal node's hash is correctly computed from its children.
func IsValidMerkleTree(tree []HexString, nodeHash NodeHash) bool {
	if len(tree) == 0 {
		return false
	}

	// Check every node to ensure children produce the correct value
	for i, node := range tree {
		left := LeftChildIndex(i)
		right := RightChildIndex(i)

		if right < len(tree) {
			expected := nodeHash(tree[left], tree[right])
			if expected != node {
				return false
			}
		}
	}
	return true
}

// LeafHashFromInput computes the hash of a leaf, ensuring consistency with tree construction.
// The leaf parameter can be either an integer index or a value of type T.
// Returns an error if the index is invalid.
func (m *MerkleTreeImpl[T]) LeafHashFromInput(leaf any) (HexString, error) {
	switch v := leaf.(type) {
	case int:
		if v < 0 || v >= len(m.Values) {
			return "", fmt.Errorf("%w: leaf index %d (max: %d)", ErrInvalidIndex, v, len(m.Values)-1)
		}
		return m.LeafHash(m.Values[v].Value), nil
	default:
		return m.LeafHash(v.(T)), nil
	}
}

// GetProof generates a Merkle proof for a specific value.
// The leaf parameter can be either an integer index or a value of type T.
// Returns the proof as a slice of hex strings, or an error if the value is not found.
func (m *MerkleTreeImpl[T]) GetProof(leaf any) ([]HexString, error) {
	valueIndex, err := m.getLeafIndex(leaf)
	if err != nil {
		return nil, err
	}

	if err := m.validateValueAt(valueIndex); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	treeIndex := m.Values[valueIndex].TreeIndex
	bytesTree := make([]BytesLike, len(m.Tree))
	for i, hexStr := range m.Tree {
		hexStrVal, err := ToBytes(hexStr)
		if err != nil {
			return nil, fmt.Errorf("error converting tree node %d: %w", i, err)
		}
		bytesTree[i] = hexStrVal
	}

	proof, err := GetProof(bytesTree, treeIndex)
	if err != nil {
		return nil, fmt.Errorf("error generating proof: %w", err)
	}

	// Empty proof is valid for single-value trees (root is the leaf)
	return proof, nil
}

// Verify checks if a proof is valid for a given leaf.
// The leaf parameter can be either an integer index or a value of type T.
// Returns true if the proof is valid, false otherwise.
func (m *MerkleTreeImpl[T]) Verify(leaf any, proof []HexString) (bool, error) {
	bytesProof := make([]BytesLike, len(proof))
	for i, hexStr := range proof {
		proofVal, err := ToBytes(hexStr)
		if err != nil {
			return false, fmt.Errorf("error converting proof element %d: %w", i, err)
		}
		bytesProof[i] = proofVal
	}

	leafHash, err := m.LeafHashFromInput(leaf)
	if err != nil {
		return false, err
	}

	hashFunc := m.NodeHash
	if hashFunc == nil {
		hashFunc = StandardNodeHash
	}

	computedRoot, err := ProcessProof(leafHash, bytesProof, hashFunc)
	if err != nil {
		return false, fmt.Errorf("error processing proof: %w", err)
	}

	return computedRoot == m.Root(), nil
}

// Validate verifies if the tree is structurally valid.
// It checks all values and the overall tree structure.
// Returns an error if any validation fails.
func (m *MerkleTreeImpl[T]) Validate() error {
	for i := range m.Values {
		if err := m.validateValueAt(i); err != nil {
			return fmt.Errorf("validation failed at index %d: %w", i, err)
		}
	}

	if !IsValidMerkleTree(m.Tree, m.NodeHash) {
		return fmt.Errorf("merkle tree structure is invalid")
	}

	return nil
}
