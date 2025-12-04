package merkletree

import (
	"fmt"
)

// SimpleMerkleTree represents a Merkle tree with standard hashing.
// It's a simpler variant that works with BytesLike values.
type SimpleMerkleTree struct {
	MerkleTreeImpl[BytesLike]
}

// SimpleMerkleTreeOptions represents the options for the Simple Merkle tree.
type SimpleMerkleTreeOptions struct {
	MerkleTreeOptions        // Include base Merkle tree options
	NodeHash          NodeHash // Custom node hash function (optional)
}

// SimpleMerkleTreeData represents the exportable data of a Simple Merkle tree.
// This format can be serialized to JSON for storage or transmission.
type SimpleMerkleTreeData struct {
	Format string `json:"format"` // Format version identifier
	Tree   []HexString `json:"tree"`   // Complete tree structure
	Values []struct {
		Value     BytesLike `json:"value"`
		TreeIndex int       `json:"treeIndex"`
	} `json:"values"` // Values with their tree positions
	Hash string `json:"hash"` // Hash function identifier
}

// FormatLeaf converts a value to a hashed format for insertion in the Merkle tree.
// This uses the standard leaf hash function.
func FormatLeaf(value BytesLike) HexString {
	return StandardLeafHash(value)
}

// NewSimpleMerkleTree creates a new SimpleMerkleTree with the given values.
// Optionally accepts a custom node hash function via options.
// Returns an error if tree construction fails.
func NewSimpleMerkleTree(values []BytesLike, options SimpleMerkleTreeOptions) (*SimpleMerkleTree, error) {
	options.MerkleTreeOptions = NewMerkleTreeOptions(&options.MerkleTreeOptions)

	// Use standard node hash if not provided
	if options.NodeHash == nil {
		options.NodeHash = StandardNodeHash
	}

	tree, indexedValues, err := PrepareMerkleTree(values, options.MerkleTreeOptions, FormatLeaf, options.NodeHash)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare merkle tree: %w", err)
	}

	// Build hash lookup map
	hashLookup := make(map[HexString]int)
	for i, v := range indexedValues {
		hash := FormatLeaf(v.Value)
		hashLookup[hash] = i
	}

	return &SimpleMerkleTree{
		MerkleTreeImpl[BytesLike]{
			Tree:       tree,
			Values:     indexedValues,
			LeafHash:   FormatLeaf,
			NodeHash:   options.NodeHash,
			HashLookup: hashLookup,
		},
	}, nil
}

// VerifySimpleMerkleTree verifies a Merkle proof for a specific value.
// This is a standalone function that can verify proofs without instantiating a tree.
// Returns true if the proof is valid, false otherwise.
func VerifySimpleMerkleTree(root BytesLike, leaf BytesLike, proof []BytesLike, nodeHash NodeHash) (bool, error) {
	leafHash := StandardLeafHash(leaf)

	// Use standard node hash if not provided
	if nodeHash == nil {
		nodeHash = StandardNodeHash
	}

	// Compute the root derived from the proof
	computedRoot, err := ProcessProof(leafHash, proof, nodeHash)
	if err != nil {
		return false, fmt.Errorf("error processing proof: %w", err)
	}

	// Compare computed root with expected root
	computedRootVal, err := ToHex(computedRoot)
	if err != nil {
		return false, fmt.Errorf("error converting computed root: %w", err)
	}

	rootVal, err := ToHex(root)
	if err != nil {
		return false, fmt.Errorf("error converting expected root: %w", err)
	}

	return computedRootVal == rootVal, nil
}

// Dump exports the tree data for debugging, storage, or transmission.
// The exported data can be serialized to JSON and later reconstructed.
func (m *SimpleMerkleTree) Dump() SimpleMerkleTreeData {
	// Convert values to the format with JSON tags
	values := make([]struct {
		Value     BytesLike `json:"value"`
		TreeIndex int       `json:"treeIndex"`
	}, len(m.Values))

	for i, v := range m.Values {
		values[i].Value = v.Value
		values[i].TreeIndex = v.TreeIndex
	}

	return SimpleMerkleTreeData{
		Format: "simple-v1",
		Tree:   m.Tree,
		Values: values,
		Hash:   "custom",
	}
}
