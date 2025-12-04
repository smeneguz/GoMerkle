# GoMerkle

A robust and efficient Merkle tree implementation in Go, compatible with OpenZeppelin's Merkle tree standards. This library provides cryptographically secure Merkle trees with support for proof generation and verification.

[![CI](https://github.com/smeneguz/GoMerkle/actions/workflows/ci.yml/badge.svg)](https://github.com/smeneguz/GoMerkle/actions/workflows/ci.yml)
[![CodeQL](https://github.com/smeneguz/GoMerkle/actions/workflows/codeql.yml/badge.svg)](https://github.com/smeneguz/GoMerkle/actions/workflows/codeql.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/smeneguz/GoMerkle.svg)](https://pkg.go.dev/github.com/smeneguz/GoMerkle)
[![Go Report Card](https://goreportcard.com/badge/github.com/smeneguz/GoMerkle)](https://goreportcard.com/report/github.com/smeneguz/GoMerkle)
[![codecov](https://codecov.io/gh/smeneguz/GoMerkle/branch/main/graph/badge.svg)](https://codecov.io/gh/smeneguz/GoMerkle)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **OpenZeppelin Compatible**: Standard Merkle tree implementation compatible with OpenZeppelin contracts
- **Type-Safe**: Built with Go generics for type safety and flexibility
- **Multiple Implementations**:
  - `StandardMerkleTree`: OpenZeppelin-compatible with Keccak256 hashing
  - `SimpleMerkleTree`: Simple implementation for byte-like values
- **Proof Generation**: Generate and verify Merkle proofs efficiently
- **Multi-Proof Support**: Support for verifying multiple leaves at once
- **Configurable**: Optional leaf sorting for consistent tree structure
- **Well-Tested**: Comprehensive test suite with high coverage
- **Zero Dependencies**: Only uses Go standard library and `golang.org/x/crypto`

## Installation

```bash
go get github.com/smeneguz/GoMerkle
```

## Quick Start

### StandardMerkleTree

The `StandardMerkleTree` is compatible with OpenZeppelin's Merkle tree implementation and uses Keccak256 hashing:

```go
package main

import (
    "fmt"
    "log"
    "github.com/smeneguz/GoMerkle/merkletree"
)

func main() {
    // Create a list of values
    values := []string{"alice", "bob", "charlie", "dave"}

    // Create the Merkle tree
    tree, err := merkletree.NewStandardMerkleTree(values, merkletree.MerkleTreeOptions{})
    if err != nil {
        log.Fatal(err)
    }

    // Get the root hash
    root := tree.Root()
    fmt.Println("Merkle Root:", root)

    // Generate a proof for a specific value
    proof, err := tree.GetProof("bob")
    if err != nil {
        log.Fatal(err)
    }

    // Verify the proof
    valid, err := tree.Verify("bob", proof)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Proof valid:", valid) // true
}
```

### SimpleMerkleTree

The `SimpleMerkleTree` is a simpler implementation that works with byte-like values:

```go
package main

import (
    "fmt"
    "log"
    "github.com/smeneguz/GoMerkle/merkletree"
)

func main() {
    // Create a list of byte-like values
    values := []merkletree.BytesLike{
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333333333333333333333333333",
    }

    // Create the tree
    tree, err := merkletree.NewSimpleMerkleTree(values, merkletree.SimpleMerkleTreeOptions{})
    if err != nil {
        log.Fatal(err)
    }

    // Get the root
    root := tree.Root()
    fmt.Println("Root:", root)

    // Generate and verify proof
    proof, err := tree.GetProof(values[0])
    if err != nil {
        log.Fatal(err)
    }

    valid, err := tree.Verify(values[0], proof)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Valid:", valid) // true
}
```

## API Documentation

### StandardMerkleTree

#### Creating a Tree

```go
tree, err := merkletree.NewStandardMerkleTree(values, options)
```

**Parameters:**
- `values`: Slice of any type (uses Go generics)
- `options`: `MerkleTreeOptions` with the following fields:
  - `SortLeaves` (bool): Sort leaves before building the tree (default: true)

#### Methods

- `Root() HexString`: Returns the root hash of the tree
- `GetProof(leaf) ([]HexString, error)`: Generates a proof for a value or index
- `Verify(leaf, proof) (bool, error)`: Verifies a proof for a given value
- `Validate() error`: Validates the entire tree structure
- `Dump() StandardMerkleTreeData`: Exports tree data for serialization

#### Standalone Verification

```go
valid, err := merkletree.VerifyStandardMerkleTree(root, leaf, proof)
```

### SimpleMerkleTree

Similar API to `StandardMerkleTree` but works with `BytesLike` values and accepts custom hash functions:

```go
options := merkletree.SimpleMerkleTreeOptions{
    MerkleTreeOptions: merkletree.MerkleTreeOptions{SortLeaves: true},
    NodeHash: customHashFunc, // Optional: defaults to StandardNodeHash
}
tree, err := merkletree.NewSimpleMerkleTree(values, options)
```

## Configuration Options

### Leaf Sorting

By default, leaves are sorted before building the tree. This ensures that trees with the same values but different input orders produce the same root:

```go
options := merkletree.MerkleTreeOptions{
    SortLeaves: true, // default
}
```

Disable sorting if you need to preserve input order:

```go
options := merkletree.MerkleTreeOptions{
    SortLeaves: false,
}
```

## Examples

### Using with Different Types

```go
// Strings
strTree, _ := merkletree.NewStandardMerkleTree(
    []string{"a", "b", "c"},
    merkletree.MerkleTreeOptions{},
)

// Numbers
numTree, _ := merkletree.NewStandardMerkleTree(
    []uint64{100, 200, 300},
    merkletree.MerkleTreeOptions{},
)

// Custom structs work too!
type User struct {
    Name string
    ID   int
}
userTree, _ := merkletree.NewStandardMerkleTree(
    []User{{Name: "Alice", ID: 1}, {Name: "Bob", ID: 2}},
    merkletree.MerkleTreeOptions{},
)
```

### Proof by Index

You can get a proof by index instead of value:

```go
proof, err := tree.GetProof(0) // Get proof for first element
```

### Exporting Tree Data

Export tree data to JSON for storage or transmission:

```go
data := tree.Dump()
jsonData, err := json.MarshalIndent(data, "", "  ")
if err != nil {
    log.Fatal(err)
}

// Save to file
os.WriteFile("merkle-tree.json", jsonData, 0644)
```

## OpenZeppelin Compatibility

This library is designed to be compatible with OpenZeppelin's Merkle tree implementation:

- Uses Keccak256 (Ethereum's SHA3) for hashing
- Uses the same ABI encoding for leaf values
- Produces identical roots for the same input data
- Proofs can be verified in Solidity contracts using OpenZeppelin's `MerkleProof` library

### Verifying in Solidity

```solidity
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MyContract {
    bytes32 public merkleRoot;

    function verify(
        bytes32[] calldata proof,
        bytes32 leaf
    ) public view returns (bool) {
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }
}
```

## Testing

Run the test suite:

```bash
go test ./merkletree/... -v
```

Run with coverage:

```bash
go test ./merkletree/... -cover
```

## Performance

GoMerkle is optimized for performance:

- Efficient tree construction using flat array representation
- Minimal memory allocations
- Fast proof generation and verification

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Silvio Meneguzzo**

- GitHub: [@smeneguz](https://github.com/smeneguz)

## Acknowledgments

- Inspired by [OpenZeppelin's Merkle Tree library](https://github.com/OpenZeppelin/merkle-tree)
- Uses Keccak256 hashing from `golang.org/x/crypto`

## References

- [Merkle Tree - Wikipedia](https://en.wikipedia.org/wiki/Merkle_tree)
- [OpenZeppelin MerkleProof Documentation](https://docs.openzeppelin.com/contracts/4.x/api/utils#MerkleProof)
- [Ethereum Merkle Patricia Trees](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)
