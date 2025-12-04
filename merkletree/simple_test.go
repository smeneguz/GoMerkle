package merkletree

import (
	"testing"
)

func TestNewSimpleMerkleTree(t *testing.T) {
	values := []BytesLike{
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
		"0x3333333333333333333333333333333333333333333333333333333333333333",
		"0x4444444444444444444444444444444444444444444444444444444444444444",
	}

	tree, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create simple merkle tree: %v", err)
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

func TestSimpleMerkleTreeGetProof(t *testing.T) {
	values := []BytesLike{
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
		"0x3333333333333333333333333333333333333333333333333333333333333333",
		"0x4444444444444444444444444444444444444444444444444444444444444444",
	}

	tree, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Get proof for the second value
	testLeaf := values[1]
	proof, err := tree.GetProof(testLeaf)
	if err != nil {
		t.Fatalf("Failed to get proof: %v", err)
	}

	// Proof should not be empty
	if len(proof) == 0 {
		t.Error("Proof should not be empty")
	}

	// Convert proof to BytesLike for verification
	proofBytes := make([]BytesLike, len(proof))
	for i, p := range proof {
		proofBytes[i] = p
	}

	// Verify the proof
	valid, err := VerifySimpleMerkleTree(tree.Root(), testLeaf, proofBytes, nil)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	if !valid {
		t.Error("Proof should be valid")
	}
}

func TestSimpleMerkleTreeVerify(t *testing.T) {
	values := []BytesLike{
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
		"0x3333333333333333333333333333333333333333333333333333333333333333",
	}

	tree, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Test valid proof
	testLeaf := values[0]
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

	// Test invalid proof (wrong leaf)
	wrongLeaf := BytesLike("0x5555555555555555555555555555555555555555555555555555555555555555")
	valid, err = tree.Verify(wrongLeaf, proof)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if valid {
		t.Error("Invalid proof should verify as false")
	}
}

func TestSimpleMerkleTreeValidate(t *testing.T) {
	values := []BytesLike{
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
	}

	tree, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Validate should succeed for a well-formed tree
	err = tree.Validate()
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}
}

func TestSimpleMerkleTreeDump(t *testing.T) {
	values := []BytesLike{
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
	}

	tree, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
	if err != nil {
		t.Fatalf("Failed to create merkle tree: %v", err)
	}

	// Dump the tree
	data := tree.Dump()

	// Verify dump format
	if data.Format != "simple-v1" {
		t.Errorf("Expected format 'simple-v1', got '%s'", data.Format)
	}

	if len(data.Tree) == 0 {
		t.Error("Dumped tree should not be empty")
	}

	if len(data.Values) != len(values) {
		t.Errorf("Expected %d values in dump, got %d", len(values), len(data.Values))
	}
}

func TestSimpleMerkleTreeWithSortedLeaves(t *testing.T) {
	values := []BytesLike{
		"0x4444444444444444444444444444444444444444444444444444444444444444",
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x3333333333333333333333333333333333333333333333333333333333333333",
		"0x2222222222222222222222222222222222222222222222222222222222222222",
	}

	// Create tree with sorted leaves
	tree1, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{
		MerkleTreeOptions: MerkleTreeOptions{SortLeaves: true},
	})
	if err != nil {
		t.Fatalf("Failed to create sorted tree: %v", err)
	}

	// Create tree with different order but same values and sorting
	valuesShuffled := []BytesLike{
		"0x2222222222222222222222222222222222222222222222222222222222222222",
		"0x4444444444444444444444444444444444444444444444444444444444444444",
		"0x1111111111111111111111111111111111111111111111111111111111111111",
		"0x3333333333333333333333333333333333333333333333333333333333333333",
	}

	tree2, err := NewSimpleMerkleTree(valuesShuffled, SimpleMerkleTreeOptions{
		MerkleTreeOptions: MerkleTreeOptions{SortLeaves: true},
	})
	if err != nil {
		t.Fatalf("Failed to create sorted tree 2: %v", err)
	}

	// Both trees should have the same root because leaves are sorted
	if tree1.Root() != tree2.Root() {
		t.Error("Sorted trees with same values should have identical roots")
	}
}

func TestSimpleMerkleTreeErrors(t *testing.T) {
	t.Run("empty tree", func(t *testing.T) {
		values := []BytesLike{}
		_, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
		if err == nil {
			t.Error("Should fail to create tree with no values")
		}
	})

	t.Run("proof for non-existent value", func(t *testing.T) {
		values := []BytesLike{
			"0x1111111111111111111111111111111111111111111111111111111111111111",
		}
		tree, err := NewSimpleMerkleTree(values, SimpleMerkleTreeOptions{})
		if err != nil {
			t.Fatalf("Failed to create tree: %v", err)
		}

		nonExistent := BytesLike("0x9999999999999999999999999999999999999999999999999999999999999999")
		_, err = tree.GetProof(nonExistent)
		if err == nil {
			t.Error("Should fail to get proof for non-existent value")
		}
	})
}
