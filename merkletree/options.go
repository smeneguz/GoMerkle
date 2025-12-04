package merkletree

// MerkleTreeOptions defines configuration options for building a Merkle tree.
type MerkleTreeOptions struct {
	// SortLeaves indicates whether leaves should be sorted before building the tree.
	// Sorting leaves makes multi-proofs more efficient and ensures consistent tree
	// structure regardless of input order.
	SortLeaves bool `json:"sortLeaves"`
}

// DefaultOptions represents the default configuration for a Merkle tree.
// By default, leaves are sorted to enable more efficient multi-proofs.
var DefaultOptions = MerkleTreeOptions{
	SortLeaves: true,
}

// NewMerkleTreeOptions creates a MerkleTreeOptions object with provided values.
// If options is nil, returns DefaultOptions.
// This function properly handles the zero-value case for boolean fields.
func NewMerkleTreeOptions(options *MerkleTreeOptions) MerkleTreeOptions {
	if options == nil {
		return DefaultOptions
	}
	return *options
}
