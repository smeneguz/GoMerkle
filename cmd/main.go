package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/smeneguz/GoMerkle/merkletree"
)

func main() {
	fmt.Println("Starting SimpleMerkleTree test")

	// 1. Create an array of data to include in the tree
	values := []merkletree.BytesLike{
		"hello",
		"0x2222",
		"0x3333",
		"0x4444",
	}

	// 2. Create the Merkle tree
	tree, err := merkletree.NewSimpleMerkleTree(values, merkletree.SimpleMerkleTreeOptions{})
	if err != nil {
		log.Fatalf("Error creating Merkle tree: %v", err)
	}

	// 3. Print the tree root
	fmt.Println("Merkle Root:", tree.Root())

	// 4. Select a value from the tree to test the proof
	testLeaf := values[2] // "0x3333"

	// Generate the proof for the selected value
	proof, err := tree.GetProof(testLeaf)
	if err != nil {
		log.Fatalf("Error generating proof: %v", err)
	}

	// 5. Print the generated proof
	fmt.Println("\nGenerated Proof:")
	for i, p := range proof {
		fmt.Printf("  Step %d: %s\n", i+1, p)
	}

	// 6. Convert the proof to BytesLike
	proofBytes := make([]merkletree.BytesLike, len(proof))
	for i, p := range proof {
		proofVal, err := merkletree.ToBytes(p)
		if err != nil {
			log.Fatalf("Error converting proof element %d: %v", i, err)
		}
		proofBytes[i] = proofVal
	}

	// 7. Verify if the proof is valid
	isValid, err := merkletree.VerifySimpleMerkleTree(tree.Root(), testLeaf, proofBytes, nil)
	if err != nil {
		log.Fatalf("Error verifying proof: %v", err)
	}
	fmt.Println("\nProof valid?", isValid)

	// 8. Test the tree dump
	treeData := tree.Dump()
	jsonData, err := json.MarshalIndent(treeData, "", "  ")
	if err != nil {
		log.Fatalf("Error serializing JSON: %v", err)
	}
	fmt.Println("\nMerkle Tree JSON:\n", string(jsonData))

	// Create tmp directory if it doesn't exist
	if err := os.MkdirAll("tmp", 0755); err != nil {
		log.Fatalf("Error creating tmp directory: %v", err)
	}

	filename := "tmp/jsonMerkle.json"
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		log.Fatalf("Error writing file: %v", err)
	}

	fmt.Printf("\nMerkle tree successfully saved to %s\n", filename)
}
