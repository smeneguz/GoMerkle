package merkletree

import "fmt"

// StandardMerkleTree represents a Merkle tree with standard encoding,
// compatible with OpenZeppelin's Merkle tree implementation.
// It uses Keccak256 hashing and ABI-style encoding.
type StandardMerkleTree[T any] struct {
	MerkleTreeImpl[T]
}

// NewStandardMerkleTree creates a new StandardMerkleTree with the given values.
// The tree uses Keccak256 hashing and is compatible with OpenZeppelin contracts.
// Returns an error if tree construction fails.
func NewStandardMerkleTree[T any](values []T, options MerkleTreeOptions) (*StandardMerkleTree[T], error) {
	options = NewMerkleTreeOptions(&options) // Use default options if not specified

	tree, indexedValues, err := PrepareMerkleTree(values, options, StandardLeafHash[T], StandardNodeHash)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare merkle tree: %w", err)
	}

	// Build hash lookup map
	hashLookup := make(map[HexString]int)
	for i, v := range indexedValues {
		hash := StandardLeafHash(v.Value)
		hashLookup[hash] = i
	}

	return &StandardMerkleTree[T]{
		MerkleTreeImpl: MerkleTreeImpl[T]{
			Tree:       tree,
			Values:     indexedValues,
			LeafHash:   StandardLeafHash[T],
			NodeHash:   StandardNodeHash,
			HashLookup: hashLookup,
		},
	}, nil
}

// VerifyStandardMerkleTree verifies a Merkle proof for a specific value.
// This is a standalone function that can verify proofs without instantiating a tree.
// Returns true if the proof is valid, false otherwise.
func VerifyStandardMerkleTree[T any](root BytesLike, leaf T, proof []BytesLike) (bool, error) {
	leafHash := StandardLeafHash(leaf)

	// Compute the root derived from the proof
	computedRoot, err := ProcessProof(leafHash, proof, StandardNodeHash)
	if err != nil {
		return false, fmt.Errorf("error processing proof: %w", err)
	}

	computedRootVal, err := ToHex(computedRoot)
	if err != nil {
		return false, fmt.Errorf("error converting computed root: %w", err)
	}

	rootVal, err := ToHex(root)
	if err != nil {
		return false, fmt.Errorf("error converting expected root: %w", err)
	}

	// Compare computed root with expected root
	return computedRootVal == rootVal, nil
}

// StandardMerkleTreeData represents the exportable data of a Standard Merkle tree.
// This format can be serialized to JSON for storage or transmission.
type StandardMerkleTreeData[T any] struct {
	Format string `json:"format"` // Format version identifier
	Tree   []HexString `json:"tree"`   // Complete tree structure
	Values []struct {
		Value     T   `json:"value"`
		TreeIndex int `json:"treeIndex"`
	} `json:"values"` // Values with their tree positions
}

// Dump exports the tree data for debugging, storage, or transmission.
// The exported data can be serialized to JSON and later reconstructed.
func (m *StandardMerkleTree[T]) Dump() StandardMerkleTreeData[T] {
	// Convert values to the format with JSON tags
	values := make([]struct {
		Value     T   `json:"value"`
		TreeIndex int `json:"treeIndex"`
	}, len(m.Values))

	for i, v := range m.Values {
		values[i].Value = v.Value
		values[i].TreeIndex = v.TreeIndex
	}

	return StandardMerkleTreeData[T]{
		Format: "standard-v1",
		Tree:   m.Tree,
		Values: values,
	}
}
