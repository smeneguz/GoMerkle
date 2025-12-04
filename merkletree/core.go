package merkletree

import (
	"fmt"
	"math"
	"sort"
)

// MultiProof represents a multi-proof for verifying multiple leaves at once.
// It contains the leaves to verify, the proof nodes, and flags indicating
// which nodes should be combined during verification.
type MultiProof struct {
	Leaves     []HexString // Hashes of the leaves included in the proof
	Proof      []HexString // List of nodes needed to compute the root
	ProofFlags []bool      // Indicates which nodes should be combined
}

// IsTreeNode checks if index i is a valid node in the tree.
func IsTreeNode(tree []BytesLike, i int) bool {
	return i >= 0 && i < len(tree)
}

// IsInternalNode checks if index i is an internal node of the Merkle tree.
// An internal node is one that has at least a left child.
func IsInternalNode(tree []BytesLike, i int) bool {
	return IsTreeNode(tree, LeftChildIndex(i))
}

// IsLeafNode checks if index i is a leaf node in the Merkle tree.
// A leaf node is valid but has no children.
func IsLeafNode(tree []BytesLike, i int) bool {
	return IsTreeNode(tree, i) && !IsInternalNode(tree, i)
}

// CheckLeafNode verifies that an index corresponds to a leaf node.
// Returns an error if the index is not a leaf.
func CheckLeafNode(tree []BytesLike, i int) error {
	if !IsLeafNode(tree, i) {
		return ErrNotLeafNode
	}
	return nil
}

// IsValidMerkleNode checks if a node is a valid 32-byte Merkle node.
func IsValidMerkleNode(node BytesLike) bool {
	bytes, err := ToBytes(node)
	if err != nil {
		return false
	}
	return len(bytes) == 32
}

// CheckValidMerkleNode verifies that a node is a valid 32-byte Merkle node.
// Returns an error if the node is invalid.
func CheckValidMerkleNode(node BytesLike) error {
	if !IsValidMerkleNode(node) {
		return ErrInvalidNode
	}
	return nil
}

// MakeMerkleTree builds a Merkle tree from a list of leaf hashes.
// The tree is represented as a flat array where the root is at index 0.
// Returns an error if the input is empty.
func MakeMerkleTree(hashes []BytesLike, nodeHash NodeHash) ([]HexString, error) {
	if len(hashes) == 0 {
		return nil, ErrEmptyTree
	}

	// Convert all hashes to HexString
	leaves := make([]HexString, len(hashes))
	for i, h := range hashes {
		leaf, err := ToHex(h)
		if err != nil {
			return nil, fmt.Errorf("invalid hash at index %d: %w", i, err)
		}
		leaves[i] = leaf
	}

	// Build the Merkle tree
	// Tree layout: [root, internal nodes..., leaves...]
	tree := make([]HexString, 2*len(leaves)-1)
	copy(tree[len(tree)-len(leaves):], leaves)

	// Generate internal nodes from bottom to top
	for i := len(tree) - len(leaves) - 1; i >= 0; i-- {
		leftChild := tree[LeftChildIndex(i)]
		rightChild := tree[RightChildIndex(i)]
		tree[i] = nodeHash(leftChild, rightChild)
	}

	return tree, nil
}

// GetProof generates a Merkle proof for a specific leaf node.
// The proof consists of sibling hashes needed to recompute the root.
// Returns an error if the index is not a valid leaf.
func GetProof(tree []BytesLike, index int) ([]HexString, error) {
	if err := CheckLeafNode(tree, index); err != nil {
		return nil, err
	}

	var proof []HexString
	for index > 0 {
		siblingIdx := SiblingIndex(index)
		value, err := ToHex(tree[siblingIdx])
		if err != nil {
			return nil, fmt.Errorf("invalid sibling at index %d: %w", siblingIdx, err)
		}
		proof = append(proof, value)
		index = ParentIndex(index)
	}
	return proof, nil
}

// ProcessProof verifies a proof and computes the resulting root.
// It applies the hash function repeatedly, combining the leaf with proof nodes.
// Returns an error if any node is invalid.
func ProcessProof(leaf BytesLike, proof []BytesLike, nodeHash NodeHash) (HexString, error) {
	// Verify that the leaf node is valid
	if err := CheckValidMerkleNode(leaf); err != nil {
		return "", fmt.Errorf("invalid leaf: %w", err)
	}

	// Verify that all proof elements are valid nodes
	for i, node := range proof {
		if err := CheckValidMerkleNode(node); err != nil {
			return "", fmt.Errorf("invalid proof node at index %d: %w", i, err)
		}
	}

	// Apply the hash function, reducing the proof to a single value
	result, err := ToHex(leaf)
	if err != nil {
		return "", fmt.Errorf("error converting leaf to hex: %w", err)
	}

	for _, sibling := range proof {
		siblingHex, err := ToHex(sibling)
		if err != nil {
			return "", fmt.Errorf("error converting sibling to hex: %w", err)
		}
		result = nodeHash(result, siblingHex)
	}

	resultHex, err := ToHex(result)
	if err != nil {
		return "", fmt.Errorf("error converting result to hex: %w", err)
	}
	return resultHex, nil
}

// GetMultiProof generates a multi-proof for a set of leaf indices.
// Multi-proofs allow verifying multiple leaves more efficiently than
// individual proofs by sharing common proof nodes.
// Returns an error if no indices are provided.
func GetMultiProof(tree []BytesLike, indices []int) (MultiProof, error) {
	if len(indices) == 0 {
		return MultiProof{}, ErrEmptyTree
	}

	var proof []HexString
	var proofFlags []bool
	stack := make([]int, len(indices))
	copy(stack, indices)

	for len(stack) > 0 && stack[0] > 0 {
		j := stack[0]
		stack = stack[1:]

		s := SiblingIndex(j)
		p := ParentIndex(j)

		if len(stack) > 0 && s == stack[0] {
			proofFlags = append(proofFlags, true)
			stack = stack[1:]
		} else {
			proofFlags = append(proofFlags, false)
			proofVal, err := ToHex(tree[s])
			if err != nil {
				return MultiProof{}, fmt.Errorf("invalid tree node at index %d: %w", s, err)
			}
			proof = append(proof, proofVal)
		}

		stack = append(stack, p)
	}

	leavesHex := make([]HexString, len(indices))
	for i, idx := range indices {
		leafHex, err := ToHex(tree[idx])
		if err != nil {
			return MultiProof{}, fmt.Errorf("invalid leaf at index %d: %w", idx, err)
		}
		leavesHex[i] = leafHex
	}

	return MultiProof{
		Leaves:     leavesHex,
		Proof:      proof,
		ProofFlags: proofFlags,
	}, nil
}

// ProcessMultiProof verifies a multi-proof and computes the resulting root.
// Returns an error if the multi-proof is invalid.
func ProcessMultiProof(multiproof MultiProof, nodeHash NodeHash) (HexString, error) {
	stack := make([]HexString, len(multiproof.Leaves))
	copy(stack, multiproof.Leaves)
	proof := make([]HexString, len(multiproof.Proof))
	copy(proof, multiproof.Proof)

	for _, flag := range multiproof.ProofFlags {
		if len(stack) < 1 || (!flag && len(proof) < 1) {
			return "", ErrInvalidMultiProof
		}

		a := stack[0]
		stack = stack[1:]

		var b HexString
		if flag {
			if len(stack) < 1 {
				return "", ErrInvalidMultiProof
			}
			b = stack[0]
			stack = stack[1:]
		} else {
			b = proof[0]
			proof = proof[1:]
		}

		leafA, err := ToHex(a)
		if err != nil {
			return "", fmt.Errorf("invalid leaf in multi-proof: %w", err)
		}
		leafB, err := ToHex(b)
		if err != nil {
			return "", fmt.Errorf("invalid leaf in multi-proof: %w", err)
		}
		stack = append(stack, nodeHash(leafA, leafB))
	}

	if len(stack)+len(proof) != 1 {
		return "", ErrInvalidMultiProof
	}

	if len(stack) == 1 {
		return stack[0], nil
	}
	return proof[0], nil
}

// ParentIndex returns the index of the parent node for a given node.
// Returns an error if the node is the root (index 0).
func ParentIndex(i int) int {
	if i > 0 {
		return int(math.Floor((float64(i) - 1) / 2))
	}
	// Note: Callers should check i > 0 before calling this function
	return 0
}

// SiblingIndex returns the index of the sibling node for a given node.
// In a binary tree, a node's sibling is its parent's other child.
func SiblingIndex(i int) int {
	if i > 0 {
		return i - int(math.Pow(-1, float64(i%2)))
	}
	// Note: Callers should check i > 0 before calling this function
	return 0
}

// LeftChildIndex returns the index of the left child for a given node.
func LeftChildIndex(i int) int {
	return 2*i + 1
}

// RightChildIndex returns the index of the right child for a given node.
func RightChildIndex(i int) int {
	return 2*i + 2
}

// PrepareMerkleTree builds the Merkle tree and assigns correct indices to the leaves.
// It handles optional leaf sorting and returns both the tree structure and indexed values.
// Returns an error if tree construction fails.
func PrepareMerkleTree[T any](
	values []T,
	options MerkleTreeOptions,
	leafHash func(T) HexString,
	nodeHash NodeHash,
) ([]HexString, []struct {
	Value     T
	TreeIndex int
}, error) {
	// Use standard node hash if not provided
	if nodeHash == nil {
		nodeHash = StandardNodeHash
	}

	// Create structure to store hashed values
	hashedValues := make([]struct {
		Value      T
		ValueIndex int
		Hash       HexString
	}, len(values))

	// Apply hash function to leaves
	for i, value := range values {
		hashedValues[i] = struct {
			Value      T
			ValueIndex int
			Hash       HexString
		}{
			Value:      value,
			ValueIndex: i,
			Hash:       leafHash(value),
		}
	}

	// Sort leaves if option is enabled
	if options.SortLeaves {
		sort.Slice(hashedValues, func(i, j int) bool {
			result, err := Compare(hashedValues[i].Hash, hashedValues[j].Hash)
			if err != nil {
				return false
			}
			return result < 0
		})
	}

	// Build the Merkle tree
	hashes := make([]BytesLike, len(hashedValues))
	for i, v := range hashedValues {
		hashes[i] = v.Hash
	}

	tree, err := MakeMerkleTree(hashes, nodeHash)
	if err != nil {
		return nil, nil, err
	}

	// Assign correct indices to leaves
	indexedValues := make([]struct {
		Value     T
		TreeIndex int
	}, len(values))

	for leafIndex, hv := range hashedValues {
		correctedIndex := len(tree) - len(hashedValues) + leafIndex
		if correctedIndex < 0 || correctedIndex >= len(tree) {
			return nil, nil, fmt.Errorf("tree index %d out of bounds (max: %d)", correctedIndex, len(tree)-1)
		}
		indexedValues[hv.ValueIndex] = struct {
			Value     T
			TreeIndex int
		}{
			Value:     hv.Value,
			TreeIndex: correctedIndex,
		}
	}

	return tree, indexedValues, nil
}
