package merkletree

import "errors"

// Common errors returned by the merkletree package.
var (
	// ErrInvalidIndex is returned when an index is out of bounds.
	ErrInvalidIndex = errors.New("index out of bounds")

	// ErrValueNotFound is returned when a requested value does not exist in the tree.
	ErrValueNotFound = errors.New("value not found in merkle tree")

	// ErrInvalidProof is returned when a proof verification fails.
	ErrInvalidProof = errors.New("invalid merkle proof")

	// ErrEmptyTree is returned when attempting to build a tree with no elements.
	ErrEmptyTree = errors.New("cannot build merkle tree with zero elements")

	// ErrInvalidNode is returned when a merkle node is not 32 bytes.
	ErrInvalidNode = errors.New("merkle tree nodes must be 32 bytes")

	// ErrNotLeafNode is returned when an index doesn't correspond to a leaf.
	ErrNotLeafNode = errors.New("index is not a leaf node")

	// ErrInvalidMultiProof is returned when multi-proof verification fails.
	ErrInvalidMultiProof = errors.New("invalid multi-proof")

	// ErrRootHasNoParent is returned when trying to get the parent of the root node.
	ErrRootHasNoParent = errors.New("root node has no parent")

	// ErrRootHasNoSibling is returned when trying to get the sibling of the root node.
	ErrRootHasNoSibling = errors.New("root node has no sibling")
)
