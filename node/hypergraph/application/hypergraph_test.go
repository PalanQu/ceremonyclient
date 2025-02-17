package application_test

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func TestHypergraph(t *testing.T) {
	hg := application.NewHypergraph(func(shardKey application.ShardKey, phaseSet protobufs.HypergraphPhaseSet) crypto.VectorCommitmentTree {
		return &crypto.RawVectorCommitmentTree{}
	})

	// Test vertex operations
	t.Run("Vertex Operations", func(t *testing.T) {
		enc := crypto.NewMPCitHVerifiableEncryptor(1)
		pub, _, _ := ed448.GenerateKey(crand.Reader)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.RawVectorCommitmentTree{}
		for _, d := range []application.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
		}
		dataTree.Commit(false)
		v1 := application.NewVertex([32]byte{1}, [32]byte{1}, dataTree.Commit(false), dataTree.GetSize())
		v2 := application.NewVertex([32]byte{1}, [32]byte{2}, dataTree.Commit(false), dataTree.GetSize())

		// Add vertices
		err := hg.AddVertex(v1)
		if err != nil {
			t.Errorf("Failed to add vertex v1: %v", err)
		}
		err = hg.AddVertex(v2)
		if err != nil {
			t.Errorf("Failed to add vertex v2: %v", err)
		}

		// Lookup vertices
		if !hg.LookupVertex(v1) {
			t.Error("Failed to lookup vertex v1")
		}
		if !hg.LookupVertex(v2) {
			t.Error("Failed to lookup vertex v2")
		}

		// Remove vertex
		err = hg.RemoveVertex(v1)
		if err != nil {
			t.Errorf("Failed to remove vertex v1: %v", err)
		}
		if hg.LookupVertex(v1) {
			t.Error("Vertex v1 still exists after removal")
		}
		if !hg.LookupVertex(v2) {
			t.Error("Vertex v2 was incorrectly removed")
		}
	})

	// Test hyperedge operations
	t.Run("Hyperedge Operations", func(t *testing.T) {
		enc := crypto.NewMPCitHVerifiableEncryptor(1)
		pub, _, _ := ed448.GenerateKey(crand.Reader)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.RawVectorCommitmentTree{}
		for _, d := range []application.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
		}
		dataTree.Commit(false)
		v3 := application.NewVertex([32]byte{2}, [32]byte{1}, dataTree.Commit(false), dataTree.GetSize())
		v4 := application.NewVertex([32]byte{2}, [32]byte{2}, dataTree.Commit(false), dataTree.GetSize())
		hg.AddVertex(v3)
		hg.AddVertex(v4)

		h1 := application.NewHyperedge([32]byte{3}, [32]byte{1})
		h1.AddExtrinsic(v3)
		h1.AddExtrinsic(v4)

		// Add hyperedge
		err := hg.AddHyperedge(h1)
		if err != nil {
			t.Errorf("Failed to add hyperedge h1: %v", err)
		}

		// Lookup hyperedge
		if !hg.LookupHyperedge(h1) {
			t.Error("Failed to lookup hyperedge h1")
		}

		// Remove hyperedge
		err = hg.RemoveHyperedge(h1)
		if err != nil {
			t.Errorf("Failed to remove hyperedge h1: %v", err)
		}
		if hg.LookupHyperedge(h1) {
			t.Error("Hyperedge h1 still exists after removal")
		}
	})

	// Test "within" relationship
	t.Run("Within Relationship", func(t *testing.T) {

		enc := crypto.NewMPCitHVerifiableEncryptor(1)
		pub, _, _ := ed448.GenerateKey(crand.Reader)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.RawVectorCommitmentTree{}
		for _, d := range []application.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
		}
		dataTree.Commit(false)
		v5 := application.NewVertex([32]byte{4}, [32]byte{1}, dataTree.Commit(false), dataTree.GetSize())
		v6 := application.NewVertex([32]byte{4}, [32]byte{2}, dataTree.Commit(false), dataTree.GetSize())
		hg.AddVertex(v5)
		hg.AddVertex(v6)

		h2 := application.NewHyperedge([32]byte{5}, [32]byte{1})
		h2.AddExtrinsic(v5)
		h2.AddExtrinsic(v6)
		hg.AddHyperedge(h2)

		if !hg.Within(v5, h2) {
			t.Error("v5 should be within h2")
		}
		if !hg.Within(v6, h2) {
			t.Error("v6 should be within h2")
		}

		v7 := application.NewVertex([32]byte{4}, [32]byte{3}, dataTree.Commit(false), dataTree.GetSize())
		hg.AddVertex(v7)
		if hg.Within(v7, h2) {
			t.Error("v7 should not be within h2")
		}
	})

	// Test nested hyperedges
	t.Run("Nested Hyperedges", func(t *testing.T) {

		enc := crypto.NewMPCitHVerifiableEncryptor(1)
		pub, _, _ := ed448.GenerateKey(crand.Reader)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.RawVectorCommitmentTree{}
		for _, d := range []application.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
		}
		dataTree.Commit(false)
		v8 := application.NewVertex([32]byte{6}, [32]byte{1}, dataTree.Commit(false), dataTree.GetSize())
		v9 := application.NewVertex([32]byte{6}, [32]byte{2}, dataTree.Commit(false), dataTree.GetSize())
		hg.AddVertex(v8)
		hg.AddVertex(v9)

		h3 := application.NewHyperedge([32]byte{7}, [32]byte{1})
		h3.AddExtrinsic(v8)
		h4 := application.NewHyperedge([32]byte{7}, [32]byte{2})
		h4.AddExtrinsic(h3)
		h4.AddExtrinsic(v9)
		hg.AddHyperedge(h3)
		hg.AddHyperedge(h4)

		if !hg.Within(v8, h4) {
			t.Error("v8 should be within h4 (nested)")
		}
		if !hg.Within(v9, h4) {
			t.Error("v9 should be within h4 (direct)")
		}
	})

	// Test error cases
	t.Run("Error Cases", func(t *testing.T) {

		enc := crypto.NewMPCitHVerifiableEncryptor(1)
		pub, _, _ := ed448.GenerateKey(crand.Reader)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.RawVectorCommitmentTree{}
		for _, d := range []application.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
		}
		dataTree.Commit(false)
		v10 := application.NewVertex([32]byte{8}, [32]byte{1}, dataTree.Commit(false), dataTree.GetSize())

		h5 := application.NewHyperedge([32]byte{8}, [32]byte{2})
		h5.AddExtrinsic(v10)

		// Try to add hyperedge with non-existent vertex
		err := hg.AddHyperedge(h5)
		if err != application.ErrMissingExtrinsics {
			t.Errorf("Expected ErrMissingExtrinsics, got %v", err)
		}

		// Add vertex and hyperedge
		hg.AddVertex(v10)
		fmt.Println("add hyperedge")
		hg.AddHyperedge(h5)
		// Try to remove vertex that is an extrinsic
		err = hg.RemoveVertex(v10)
		if err != application.ErrIsExtrinsic {
			t.Errorf("Expected ErrIsExtrinsic, got %v", err)
		}
	})

	// Test sharding
	t.Run("Sharding", func(t *testing.T) {

		enc := crypto.NewMPCitHVerifiableEncryptor(1)
		pub, _, _ := ed448.GenerateKey(crand.Reader)
		data := enc.Encrypt(make([]byte, 20), pub)
		verenc := data[0].Compress()
		dataTree := &crypto.RawVectorCommitmentTree{}
		for _, d := range []application.Encrypted{verenc} {
			dataBytes := d.ToBytes()
			id := sha512.Sum512(dataBytes)
			dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
		}
		dataTree.Commit(false)
		v11 := application.NewVertex([32]byte{9}, [32]byte{1}, dataTree.Commit(false), dataTree.GetSize())
		v12 := application.NewVertex([32]byte{9}, [32]byte{2}, dataTree.Commit(false), dataTree.GetSize())
		hg.AddVertex(v11)
		hg.AddVertex(v12)

		shard11 := application.GetShardAddress(v11)
		shard12 := application.GetShardAddress(v12)

		if !bytes.Equal(shard11.L1[:], shard12.L1[:]) ||
			!bytes.Equal(shard11.L2[:], shard12.L2[:]) ||
			bytes.Equal(shard11.L3[:], shard12.L3[:]) {
			t.Error("v11 and v12 should be in the same L1 shard and the same L2 shard but not the same L3 shard")
		}
	})
}
