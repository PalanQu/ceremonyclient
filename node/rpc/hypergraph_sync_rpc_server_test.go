package rpc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"net"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type Operation struct {
	Type      string // "AddVertex", "RemoveVertex", "AddHyperedge", "RemoveHyperedge"
	Vertex    application.Vertex
	Hyperedge application.Hyperedge
}

func TestHypergraphSyncServer(t *testing.T) {
	numParties := 3
	numOperations := 10000
	log.Printf("Generating data")
	enc := crypto.NewMPCitHVerifiableEncryptor(1)
	pub, _, _ := ed448.GenerateKey(rand.Reader)
	data := enc.Encrypt(make([]byte, 20), pub)
	verenc := data[0].Compress()
	vertices := make([]application.Vertex, numOperations)
	dataTree := &crypto.VectorCommitmentTree{}
	for _, d := range []application.Encrypted{verenc} {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
	}
	dataTree.Commit(false)
	for i := 0; i < numOperations; i++ {
		b := make([]byte, 32)
		rand.Read(b)
		vertices[i] = application.NewVertex(
			[32]byte{},
			[32]byte(b),
			dataTree.Commit(false),
			dataTree.GetSize(),
		)
	}

	hyperedges := make([]application.Hyperedge, numOperations/10)
	for i := 0; i < numOperations/10; i++ {
		hyperedges[i] = application.NewHyperedge(
			[32]byte{},
			[32]byte{0, 0, byte((i >> 8) / 256), byte(i / 256)},
		)
		for j := 0; j < 3; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(vertices))))
			v := vertices[n.Int64()]
			hyperedges[i].AddExtrinsic(v)
		}
	}

	shardKey := application.GetShardKey(vertices[0])

	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		operations1[i] = Operation{Type: "AddVertex", Vertex: vertices[i]}
	}
	for i := 0; i < numOperations; i++ {
		op, _ := rand.Int(rand.Reader, big.NewInt(2))
		switch op.Int64() {
		case 0:
			e, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hyperedges))))
			operations2[i] = Operation{Type: "AddHyperedge", Hyperedge: hyperedges[e.Int64()]}
		case 1:
			e, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hyperedges))))
			operations2[i] = Operation{Type: "RemoveHyperedge", Hyperedge: hyperedges[e.Int64()]}
		}
	}

	clientKvdb := store.NewInMemKVDB()
	serverKvdb := store.NewInMemKVDB()
	logger, _ := zap.NewProduction()
	clientHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestclient/store"},
		clientKvdb,
		logger,
	)
	serverHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestserver/store"},
		serverKvdb,
		logger,
	)
	crdts := make([]*application.Hypergraph, numParties)
	for i := 0; i < numParties; i++ {
		crdts[i] = application.NewHypergraph()
	}

	txn, _ := serverHypergraphStore.NewTransaction(false)
	for _, op := range operations1[:250] {
		switch op.Type {
		case "AddVertex":
			id := op.Vertex.GetID()
			serverHypergraphStore.SaveVertexTree(txn, id[:], dataTree)
			crdts[0].AddVertex(op.Vertex)
		case "RemoveVertex":
			crdts[0].RemoveVertex(op.Vertex)
		case "AddHyperedge":
			crdts[0].AddHyperedge(op.Hyperedge)
		case "RemoveHyperedge":
			crdts[0].RemoveHyperedge(op.Hyperedge)
		}
	}
	txn.Commit()
	for _, op := range operations2[:500] {
		switch op.Type {
		case "AddVertex":
			crdts[0].AddVertex(op.Vertex)
		case "RemoveVertex":
			crdts[0].RemoveVertex(op.Vertex)
		case "AddHyperedge":
			crdts[0].AddHyperedge(op.Hyperedge)
		case "RemoveHyperedge":
			crdts[0].RemoveHyperedge(op.Hyperedge)
		}
	}

	txn, _ = clientHypergraphStore.NewTransaction(false)
	for _, op := range operations1[250:] {
		switch op.Type {
		case "AddVertex":
			id := op.Vertex.GetID()
			clientHypergraphStore.SaveVertexTree(txn, id[:], dataTree)
			crdts[1].AddVertex(op.Vertex)
		case "RemoveVertex":
			crdts[1].RemoveVertex(op.Vertex)
		case "AddHyperedge":
			crdts[1].AddHyperedge(op.Hyperedge)
		case "RemoveHyperedge":
			crdts[1].RemoveHyperedge(op.Hyperedge)
		}
	}
	txn.Commit()
	for _, op := range operations2[500:] {
		switch op.Type {
		case "AddVertex":
			crdts[1].AddVertex(op.Vertex)
		case "RemoveVertex":
			crdts[1].RemoveVertex(op.Vertex)
		case "AddHyperedge":
			crdts[1].AddHyperedge(op.Hyperedge)
		case "RemoveHyperedge":
			crdts[1].RemoveHyperedge(op.Hyperedge)
		}
	}

	for _, op := range operations1 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(op.Vertex)
		case "AddHyperedge":
			crdts[2].AddHyperedge(op.Hyperedge)
		case "RemoveHyperedge":
			crdts[2].RemoveHyperedge(op.Hyperedge)
		}
	}
	for _, op := range operations2 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(op.Vertex)
		case "AddHyperedge":
			crdts[2].AddHyperedge(op.Hyperedge)
		case "RemoveHyperedge":
			crdts[2].RemoveHyperedge(op.Hyperedge)
		}
	}

	crdts[0].Commit()
	crdts[1].Commit()
	crdts[2].Commit()
	err := serverHypergraphStore.SaveHypergraph(crdts[0])
	assert.NoError(t, err)
	err = clientHypergraphStore.SaveHypergraph(crdts[1])
	assert.NoError(t, err)
	serverLoad, err := serverHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	clientLoad, err := clientHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	assert.Len(t, crypto.CompareLeaves(
		crdts[0].GetVertexAdds()[shardKey].GetTree(),
		serverLoad.GetVertexAdds()[shardKey].GetTree(),
	), 0)
	assert.Len(t, crypto.CompareLeaves(
		crdts[1].GetVertexAdds()[shardKey].GetTree(),
		clientLoad.GetVertexAdds()[shardKey].GetTree(),
	), 0)
	log.Printf("Generated data")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Server: failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	protobufs.RegisterHypergraphComparisonServiceServer(
		grpcServer,
		rpc.NewHypergraphComparisonServer(logger, serverHypergraphStore, crdts[0], rpc.NewSyncController(), 10000),
	)
	log.Println("Server listening on :50051")
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Server: failed to serve: %v", err)
		}
	}()
	conn, err := grpc.DialContext(context.TODO(), "localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Client: failed to listen: %v", err)
	}
	client := protobufs.NewHypergraphComparisonServiceClient(conn)
	str, err := client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	syncController := rpc.NewSyncController()

	err = rpc.SyncTreeBidirectionally(str, logger, append(append([]byte{}, shardKey.L1[:]...), shardKey.L2[:]...), protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, clientHypergraphStore, crdts[1].GetVertexAdds()[shardKey], syncController, 10000, false)
	if err != nil {
		log.Fatalf("Client: failed to sync 1: %v", err)
	}

	leaves := crypto.CompareLeaves(
		crdts[0].GetVertexAdds()[shardKey].GetTree(),
		crdts[1].GetVertexAdds()[shardKey].GetTree(),
	)
	fmt.Println("pass completed, orphans:", len(leaves))

	crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false)
	crdts[1].GetVertexAdds()[shardKey].GetTree().Commit(false)

	str, err = client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	err = rpc.SyncTreeBidirectionally(str, logger, append(append([]byte{}, shardKey.L1[:]...), shardKey.L2[:]...), protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, clientHypergraphStore, crdts[1].GetVertexAdds()[shardKey], syncController, 10000, false)
	if err != nil {
		log.Fatalf("Client: failed to sync 2: %v", err)
	}

	if !bytes.Equal(
		crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
		crdts[1].GetVertexAdds()[shardKey].GetTree().Commit(false),
	) {
		leaves := crypto.CompareLeaves(
			crdts[0].GetVertexAdds()[shardKey].GetTree(),
			crdts[1].GetVertexAdds()[shardKey].GetTree(),
		)
		fmt.Println(len(leaves))
		log.Fatalf(
			"trees mismatch: %v %v",
			crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
			crdts[1].GetVertexAdds()[shardKey].GetTree().Commit(false),
		)
	}

	if !bytes.Equal(
		crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
		crdts[2].GetVertexAdds()[shardKey].GetTree().Commit(false),
	) {
		log.Fatalf(
			"trees did not converge to correct state: %v %v",
			crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
			crdts[2].GetVertexAdds()[shardKey].GetTree().Commit(false),
		)
	}
	t.FailNow()
}
