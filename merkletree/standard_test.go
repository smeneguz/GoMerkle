package merkletree

import (
	"testing"
)

func TestNewStandardMerkleTree(t *testing.T) {
	values := []string{"alice", "bob", "charlie", "dave"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create standard merkle tree: %v", err)
	}

	// Verify tree was created
	if tree == nil {
		t.Fatal("Tree is nil")
	}

	// Verify root is not empty
	root := tree.Root()
	if root == "" {
		t.Error("Root should not be empty")
	}

	// Verify tree has correct number of values
	if len(tree.Values) != len(values) {
		t.Errorf("Expected %d values, got %d", len(values), len(tree.Values))
	}
}

func TestStandardMerkleTreeWithNumbers(t *testing.T) {
	values := []uint64{100, 200, 300, 400}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree with numbers: %v", err)
	}

	if tree == nil {
		t.Fatal("Tree is nil")
	}

	root := tree.Root()
	if root == "" {
		t.Error("Root should not be empty")
	}
}

func TestStandardMerkleTreeGetProof(t *testing.T) {
	values := []string{"alpha", "beta", "gamma", "delta"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Get proof for the first value
	testLeaf := values[0]
	proof, err := tree.GetProof(testLeaf)
	if err != nil {
		t.Fatalf("Failed to get proof: %v", err)
	}

	// Proof should not be empty for a tree with multiple values
	if len(proof) == 0 {
		t.Error("Proof should not be empty")
	}

	// Verify the proof
	valid, err := tree.Verify(testLeaf, proof)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	if !valid {
		t.Error("Proof should be valid")
	}
}

func TestStandardMerkleTreeVerify(t *testing.T) {
	values := []string{"one", "two", "three"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Test valid proof
	testLeaf := values[1]
	proof, err := tree.GetProof(testLeaf)
	if err != nil {
		t.Fatalf("Failed to get proof: %v", err)
	}

	valid, err := tree.Verify(testLeaf, proof)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Valid proof should verify as true")
	}

	// Test with wrong value
	wrongLeaf := "four"
	valid, err = tree.Verify(wrongLeaf, proof)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if valid {
		t.Error("Proof for wrong value should be invalid")
	}
}

func TestVerifyStandardMerkleTree(t *testing.T) {
	values := []string{"test1", "test2", "test3"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	testLeaf := values[0]
	proof, err := tree.GetProof(testLeaf)
	if err != nil {
		t.Fatalf("Failed to get proof: %v", err)
	}

	// Convert proof to BytesLike
	proofBytes := make([]BytesLike, len(proof))
	for i, p := range proof {
		proofBytes[i] = p
	}

	// Use standalone verification function
	valid, err := VerifyStandardMerkleTree(tree.Root(), testLeaf, proofBytes)
	if err != nil {
		t.Fatalf("Failed to verify with standalone function: %v", err)
	}

	if !valid {
		t.Error("Standalone verification should succeed")
	}
}

func TestStandardMerkleTreeValidate(t *testing.T) {
	values := []string{"a", "b", "c"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Validate should succeed for a well-formed tree
	err = tree.Validate()
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}
}

func TestStandardMerkleTreeDump(t *testing.T) {
	values := []string{"x", "y", "z"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Dump the tree
	data := tree.Dump()

	// Verify dump format
	if data.Format != "standard-v1" {
		t.Errorf("Expected format 'standard-v1', got '%s'", data.Format)
	}

	if len(data.Tree) == 0 {
		t.Error("Dumped tree should not be empty")
	}

	if len(data.Values) != len(values) {
		t.Errorf("Expected %d values in dump, got %d", len(values), len(data.Values))
	}

	// Verify values are present
	for i, val := range data.Values {
		if val.Value != values[i] {
			t.Errorf("Value %d mismatch: expected %v, got %v", i, values[i], val.Value)
		}
	}
}

func TestStandardMerkleTreeWithSortedLeaves(t *testing.T) {
	values := []string{"delta", "alpha", "charlie", "bravo"}

	// Create tree with sorted leaves
	tree1, err := NewStandardMerkleTree(values, MerkleTreeOptions{SortLeaves: true})
	if err != nil {
		t.Fatalf("Failed to create sorted tree: %v", err)
	}

	// Create tree with different order but same values and sorting
	valuesShuffled := []string{"bravo", "delta", "alpha", "charlie"}

	tree2, err := NewStandardMerkleTree(valuesShuffled, MerkleTreeOptions{SortLeaves: true})
	if err != nil {
		t.Fatalf("Failed to create sorted tree 2: %v", err)
	}

	// Both trees should have the same root because leaves are sorted
	if tree1.Root() != tree2.Root() {
		t.Error("Sorted trees with same values should have identical roots")
	}
}

func TestStandardMerkleTreeGetProofByIndex(t *testing.T) {
	values := []string{"first", "second", "third"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Get proof by index
	proof, err := tree.GetProof(1) // Get proof for "second"
	if err != nil {
		t.Fatalf("Failed to get proof by index: %v", err)
	}

	// Verify using the actual value
	valid, err := tree.Verify(values[1], proof)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Proof obtained by index should be valid")
	}
}

func TestStandardMerkleTreeErrors(t *testing.T) {
	t.Run("empty tree", func(t *testing.T) {
		values := []string{}
		_, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
		if err == nil {
			t.Error("Should fail to create tree with no values")
		}
	})

	t.Run("proof for non-existent value", func(t *testing.T) {
		values := []string{"exists"}
		tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
		if err != nil {
			t.Fatalf("Failed to create tree: %v", err)
		}

		_, err = tree.GetProof("does-not-exist")
		if err == nil {
			t.Error("Should fail to get proof for non-existent value")
		}
	})

	t.Run("proof for invalid index", func(t *testing.T) {
		values := []string{"single"}
		tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
		if err != nil {
			t.Fatalf("Failed to create tree: %v", err)
		}

		_, err = tree.GetProof(99)
		if err == nil {
			t.Error("Should fail to get proof for invalid index")
		}
	})
}

func TestStandardMerkleTreeSingleValue(t *testing.T) {
	values := []string{"only-one"}

	tree, err := NewStandardMerkleTree(values, MerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create tree with single value: %v", err)
	}

	root := tree.Root()
	if root == "" {
		t.Error("Root should not be empty")
	}

	// For a tree with one value, proof should be empty
	proof, err := tree.GetProof(values[0])
	if err != nil {
		t.Fatalf("Failed to get proof: %v", err)
	}

	// Verify the proof
	valid, err := tree.Verify(values[0], proof)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Error("Proof for single-value tree should be valid")
	}
}
