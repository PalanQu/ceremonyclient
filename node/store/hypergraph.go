package store

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type HypergraphStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	LoadVertexTree(id []byte) (
		*crypto.RawVectorCommitmentTree,
		error,
	)
	LoadVertexData(id []byte) ([]application.Encrypted, error)
	SaveVertexTree(
		txn Transaction,
		id []byte,
		vertTree *crypto.RawVectorCommitmentTree,
	) error
	CommitAndSaveVertexData(
		txn Transaction,
		id []byte,
		data []application.Encrypted,
	) (*crypto.RawVectorCommitmentTree, []byte, error)
	LoadHypergraph() (
		*application.Hypergraph,
		error,
	)
	SaveHypergraph(
		txn Transaction,
		hg *application.Hypergraph,
	) error
	GetBranchNode(id NodeID) (*StoredBranchNode, error)
	GetLeafNode(id NodeID) (*StoredLeafNode, error)
	BatchWrite(
		txn Transaction,
		branches map[NodeID]*StoredBranchNode,
		leaves map[NodeID]*StoredLeafNode,
		deletions map[NodeID]struct{},
	) error
}

var _ HypergraphStore = (*PebbleHypergraphStore)(nil)

type PebbleHypergraphStore struct {
	db     KVDB
	logger *zap.Logger
}

func NewPebbleHypergraphStore(
	db KVDB,
	logger *zap.Logger,
) *PebbleHypergraphStore {
	return &PebbleHypergraphStore{
		db,
		logger,
	}
}

const (
	HYPERGRAPH_SHARD  = 0x09
	VERTEX_ADDS       = 0x00
	VERTEX_REMOVES    = 0x10
	VERTEX_DATA       = 0xF0
	HYPEREDGE_ADDS    = 0x01
	HYPEREDGE_REMOVES = 0x11
	SET_TREE_ROOT     = 0x00
	SET_TREE_BRANCH   = 0x01
	SET_TREE_LEAF     = 0x02
)

func hypergraphVertexAddsKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphVertexDataKey(id []byte) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_DATA}
	key = append(key, id...)
	return key
}

func hypergraphVertexRemovesKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeAddsKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeRemovesKey(shardKey application.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func shardKeyFromKey(key []byte) application.ShardKey {
	return application.ShardKey{
		L1: [3]byte(key[3:6]),
		L2: [32]byte(key[6:]),
	}
}

func SetTreeBranchKey(
	shardKey application.ShardKey,
	phaseSet byte,
	prefix []int,
) NodeID {
	key := []byte{HYPERGRAPH_SHARD, phaseSet}
	if len(prefix) == 0 {
		key = append(key, SET_TREE_ROOT)
		key = append(key, shardKey.L1[:]...)
		key = append(key, shardKey.L2[:]...)
		return NodeID(key)
	}

	key = append(key, SET_TREE_BRANCH)
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, packNibbles(prefix)...)
	return NodeID(key)
}

func SetTreeLeafKey(
	shardKey application.ShardKey,
	phaseSet byte,
	leafKey []byte,
) NodeID {
	key := []byte{HYPERGRAPH_SHARD, phaseSet}
	key = append(key, SET_TREE_LEAF)
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, leafKey...)
	return NodeID(key)
}

func (p *PebbleHypergraphStore) NewTransaction(indexed bool) (
	Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleHypergraphStore) NewOversizedBatch() (Transaction, error) {
	return p.db.NewOversizedBatch(), nil
}

func (p *PebbleHypergraphStore) LoadVertexTree(id []byte) (
	*crypto.RawVectorCommitmentTree,
	error,
) {
	tree := &crypto.RawVectorCommitmentTree{}
	var b bytes.Buffer
	vertexData, closer, err := p.db.Get(hypergraphVertexDataKey(id))
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}
	defer closer.Close()
	b.Write(vertexData)

	dec := gob.NewDecoder(&b)
	if err := dec.Decode(tree); err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}

	return tree, nil
}

func (p *PebbleHypergraphStore) LoadVertexData(id []byte) (
	[]application.Encrypted,
	error,
) {
	tree := &crypto.RawVectorCommitmentTree{}
	var b bytes.Buffer
	vertexData, closer, err := p.db.Get(hypergraphVertexDataKey(id))
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}
	defer closer.Close()
	b.Write(vertexData)

	dec := gob.NewDecoder(&b)
	if err := dec.Decode(tree); err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}

	encData := []application.Encrypted{}
	for _, d := range crypto.GetAllLeaves(tree) {
		verencData := crypto.MPCitHVerEncFromBytes(d.Value)
		encData = append(encData, verencData)
	}

	return encData, nil
}

func (p *PebbleHypergraphStore) SaveVertexTree(
	txn Transaction,
	id []byte,
	vertTree *crypto.RawVectorCommitmentTree,
) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(vertTree); err != nil {
		return errors.Wrap(err, "save vertex tree")
	}

	return errors.Wrap(
		txn.Set(hypergraphVertexDataKey(id), buf.Bytes()),
		"save vertex tree",
	)
}

func (p *PebbleHypergraphStore) CommitAndSaveVertexData(
	txn Transaction,
	id []byte,
	data []application.Encrypted,
) (*crypto.RawVectorCommitmentTree, []byte, error) {
	dataTree := application.EncryptedToVertexTree(data)
	commit := dataTree.Commit(false)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(dataTree); err != nil {
		return nil, nil, errors.Wrap(err, "commit and save vertex data")
	}

	return dataTree, commit, errors.Wrap(
		txn.Set(hypergraphVertexDataKey(id), buf.Bytes()),
		"commit and save vertex data",
	)
}

func (p *PebbleHypergraphStore) LoadHypergraph() (
	*application.Hypergraph,
	error,
) {
	hg := application.NewHypergraph(
		func(
			shardKey application.ShardKey,
			phaseSet protobufs.HypergraphPhaseSet,
		) crypto.VectorCommitmentTree {
			return NewPersistentVectorTree(p, shardKey, phaseSet)
		},
	)
	vertexAddsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS, SET_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS, SET_TREE_BRANCH},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer vertexAddsIter.Close()
	for vertexAddsIter.First(); vertexAddsIter.Valid(); vertexAddsIter.Next() {
		shardKey := make([]byte, len(vertexAddsIter.Key()))
		copy(shardKey, vertexAddsIter.Key())
		node := &StoredBranchNode{}
		var b bytes.Buffer
		b.Write(vertexAddsIter.Value())

		dec := gob.NewDecoder(&b)
		if err := dec.Decode(node); err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		tree := NewPersistentVectorTree(
			p,
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		)

		tree.tree.Root, err = tree.storedToBranch(node)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err := hg.SetIdSet(
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	vertexRemovesIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES, SET_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES, SET_TREE_BRANCH},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer vertexRemovesIter.Close()
	for vertexRemovesIter.First(); vertexRemovesIter.Valid(); vertexRemovesIter.Next() {
		shardKey := make([]byte, len(vertexRemovesIter.Key()))
		copy(shardKey, vertexRemovesIter.Key())
		node := &StoredBranchNode{}
		var b bytes.Buffer
		b.Write(vertexRemovesIter.Value())

		dec := gob.NewDecoder(&b)
		if err := dec.Decode(node); err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		tree := NewPersistentVectorTree(
			p,
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
		)

		tree.tree.Root, err = tree.storedToBranch(node)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err := hg.SetIdSet(
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	hyperedgeAddsIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS, SET_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS, SET_TREE_BRANCH},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer hyperedgeAddsIter.Close()
	for hyperedgeAddsIter.First(); hyperedgeAddsIter.Valid(); hyperedgeAddsIter.Next() {
		shardKey := make([]byte, len(hyperedgeAddsIter.Key()))
		copy(shardKey, hyperedgeAddsIter.Key())
		node := &StoredBranchNode{}
		var b bytes.Buffer
		b.Write(hyperedgeAddsIter.Value())

		dec := gob.NewDecoder(&b)
		if err := dec.Decode(node); err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		tree := NewPersistentVectorTree(
			p,
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
		)

		tree.tree.Root, err = tree.storedToBranch(node)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err := hg.SetIdSet(
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	hyperedgeRemovesIter, err := p.db.NewIter(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES, SET_TREE_ROOT},
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES, SET_TREE_BRANCH},
	)
	if err != nil {
		return nil, errors.Wrap(err, "load hypergraph")
	}
	defer hyperedgeRemovesIter.Close()
	for hyperedgeRemovesIter.First(); hyperedgeRemovesIter.Valid(); hyperedgeRemovesIter.Next() {
		shardKey := make([]byte, len(hyperedgeRemovesIter.Key()))
		copy(shardKey, hyperedgeRemovesIter.Key())
		node := &StoredBranchNode{}
		var b bytes.Buffer
		b.Write(hyperedgeRemovesIter.Value())

		dec := gob.NewDecoder(&b)
		if err := dec.Decode(node); err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		tree := NewPersistentVectorTree(
			p,
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
		)

		tree.tree.Root, err = tree.storedToBranch(node)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}

		err := hg.SetIdSet(
			shardKeyFromKey(shardKey),
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
			tree,
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
	}

	return hg, nil
}

func (p *PebbleHypergraphStore) SaveHypergraph(
	txn Transaction,
	hg *application.Hypergraph,
) error {
	hg.Commit()

	for _, vertexAdds := range hg.GetVertexAdds() {
		if vertexAdds.IsDirty() {
			err := vertexAdds.GetTree().(*PersistentVectorTree).WriteBatch(txn)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for _, vertexRemoves := range hg.GetVertexRemoves() {
		if vertexRemoves.IsDirty() {
			err := vertexRemoves.GetTree().(*PersistentVectorTree).WriteBatch(txn)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for _, hyperedgeAdds := range hg.GetHyperedgeAdds() {
		if hyperedgeAdds.IsDirty() {
			err := hyperedgeAdds.GetTree().(*PersistentVectorTree).WriteBatch(txn)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for _, hyperedgeRemoves := range hg.GetHyperedgeRemoves() {
		if hyperedgeRemoves.IsDirty() {
			err := hyperedgeRemoves.GetTree().(*PersistentVectorTree).WriteBatch(txn)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	return nil
}

func (p *PebbleHypergraphStore) GetBranchNode(id NodeID) (
	*StoredBranchNode,
	error,
) {
	data, closer, err := p.db.Get([]byte(id))
	if err != nil {
		return nil, errors.Wrap(err, "get branch node")
	}
	defer closer.Close()

	node := &StoredBranchNode{}
	var b bytes.Buffer
	b.Write(data)

	dec := gob.NewDecoder(&b)
	if err := dec.Decode(node); err != nil {
		return nil, errors.Wrap(err, "get branch node")
	}

	return node, nil
}

func (p *PebbleHypergraphStore) GetLeafNode(id NodeID) (
	*StoredLeafNode,
	error,
) {
	data, closer, err := p.db.Get([]byte(id))
	if err != nil {
		return nil, errors.Wrap(err, "get branch node")
	}
	defer closer.Close()

	node := &StoredLeafNode{}
	var b bytes.Buffer
	b.Write(data)

	dec := gob.NewDecoder(&b)
	if err := dec.Decode(node); err != nil {
		return nil, errors.Wrap(err, "get branch node")
	}

	return node, nil
}

func (p *PebbleHypergraphStore) BatchWrite(
	txn Transaction,
	branches map[NodeID]*StoredBranchNode,
	leaves map[NodeID]*StoredLeafNode,
	deletions map[NodeID]struct{},
) error {
	for id := range deletions {
		if err := txn.Delete([]byte(id)); err != nil {
			return errors.Wrap(err, "batch write")
		}
	}

	for id, node := range branches {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(node); err != nil {
			return errors.Wrap(err, "batch write")
		}

		if err := txn.Set([]byte(id), buf.Bytes()); err != nil {
			return errors.Wrap(err, "batch write")
		}
	}

	for id, node := range leaves {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(node); err != nil {
			return errors.Wrap(err, "batch write")
		}

		if err := txn.Set([]byte(id), buf.Bytes()); err != nil {
			return errors.Wrap(err, "batch write")
		}
	}

	return nil
}

// StoredBranchNode represents the serializable form of a branch node.
// Storage of trees necessarily includes the metadata because trees can be
// lazily loaded, and this metadata is sometimes the only information we need.
// Commitments should also be stored due to time cost of calculation.
type StoredBranchNode struct {
	Prefix        []int
	Commitment    []byte
	ChildrenIDs   [crypto.NodesPerBranch]NodeID
	Size          []byte
	LeafCount     int
	LongestBranch int
}

// StoredLeafNode represents the serializable form of a leaf node.
// Storage of leaves necessarily includes the value of the data as we may not
// be dynamically resolving the underlying indirect reference the value
// represents with lazy loading, but the distinction between the value and hash
// target (if present) may be important.
type StoredLeafNode struct {
	Commitment []byte
	Key        []byte
	Value      []byte
	HashTarget []byte
	Size       []byte
}

type NodeID string

type PersistentVectorTree struct {
	store         HypergraphStore
	tree          *crypto.RawVectorCommitmentTree
	shardKey      application.ShardKey
	phaseSet      byte
	addedBranches map[NodeID]*StoredBranchNode
	addedLeaves   map[NodeID]*StoredLeafNode
	deletions     map[NodeID]struct{}
}

var _ crypto.VectorCommitmentTree = (*PersistentVectorTree)(nil)

func NewPersistentVectorTree(
	store HypergraphStore,
	shardKey application.ShardKey,
	phaseSet protobufs.HypergraphPhaseSet,
) *PersistentVectorTree {
	phaseByte := byte(0x00)
	switch phaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		phaseByte = VERTEX_ADDS
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		phaseByte = VERTEX_REMOVES
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		phaseByte = HYPEREDGE_ADDS
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		phaseByte = HYPEREDGE_REMOVES
	}

	return &PersistentVectorTree{
		store:         store,
		tree:          &crypto.RawVectorCommitmentTree{},
		shardKey:      shardKey,
		phaseSet:      phaseByte,
		addedBranches: make(map[NodeID]*StoredBranchNode),
		addedLeaves:   make(map[NodeID]*StoredLeafNode),
		deletions:     make(map[NodeID]struct{}),
	}
}

func serializeBigInt(n *big.Int) []byte {
	if n == nil {
		return nil
	}
	return n.FillBytes(make([]byte, 32))
}

func deserializeBigInt(data []byte) *big.Int {
	if len(data) == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(data)
}

func branchToStored(
	shardKey application.ShardKey,
	phaseSet byte,
	prefix []int,
	node *crypto.VectorCommitmentBranchNode,
) *StoredBranchNode {
	stored := &StoredBranchNode{
		Prefix:        make([]int, len(node.Prefix)),
		Commitment:    node.Commitment,
		ChildrenIDs:   [crypto.NodesPerBranch]NodeID{},
		Size:          serializeBigInt(node.Size),
		LeafCount:     node.LeafCount,
		LongestBranch: node.LongestBranch,
	}
	copy(stored.Prefix, node.Prefix)
	for i, child := range node.Children {
		if child == nil {
			continue
		}
		switch c := child.(type) {
		case *crypto.VectorCommitmentBranchNode:
			stored.ChildrenIDs[i] = SetTreeBranchKey(
				shardKey,
				phaseSet,
				append(append(append([]int{}, prefix...), node.Prefix...), i),
			)
		case *crypto.VectorCommitmentLeafNode:
			stored.ChildrenIDs[i] = SetTreeLeafKey(
				shardKey,
				phaseSet,
				c.Key,
			)
		}
	}
	return stored
}

func leafToStored(node *crypto.VectorCommitmentLeafNode) *StoredLeafNode {
	return &StoredLeafNode{
		Key:        node.Key,
		Commitment: node.Commitment,
		Value:      node.Value,
		HashTarget: node.HashTarget,
		Size:       serializeBigInt(node.Size),
	}
}

func (t *PersistentVectorTree) storedToBranch(
	stored *StoredBranchNode,
) (*crypto.VectorCommitmentBranchNode, error) {
	node := &crypto.VectorCommitmentBranchNode{
		Prefix:        stored.Prefix,
		Commitment:    stored.Commitment,
		Children:      [crypto.NodesPerBranch]crypto.VectorCommitmentNode{},
		Size:          deserializeBigInt(stored.Size),
		LeafCount:     stored.LeafCount,
		LongestBranch: stored.LongestBranch,
	}

	for i, childID := range stored.ChildrenIDs {
		if childID == "" {
			continue
		}
		var child crypto.VectorCommitmentNode
		var err error

		if childID[2] == SET_TREE_BRANCH {
			child, err = t.loadBranchNode(childID)
		} else {
			child, err = t.loadLeafNode(childID)
		}
		if err != nil {
			return nil, err
		}
		node.Children[i] = child
	}

	return node, nil
}

func storedToLeaf(stored *StoredLeafNode) *crypto.VectorCommitmentLeafNode {
	return &crypto.VectorCommitmentLeafNode{
		Key:        stored.Key,
		Commitment: stored.Commitment,
		Value:      stored.Value,
		HashTarget: stored.HashTarget,
		Size:       deserializeBigInt(stored.Size),
	}
}

func (t *PersistentVectorTree) loadBranchNode(
	id NodeID,
) (*crypto.VectorCommitmentBranchNode, error) {
	stored, err := t.store.GetBranchNode(id)
	if err != nil {
		return nil, fmt.Errorf("failed to load branch node %s: %w", id, err)
	}
	return t.storedToBranch(stored)
}

func (t *PersistentVectorTree) loadLeafNode(id NodeID) (
	*crypto.VectorCommitmentLeafNode,
	error,
) {
	stored, err := t.store.GetLeafNode(id)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(
				err,
				fmt.Sprintf("failed to load leaf node %s", id),
			),
			"load leaf node",
		)
	}
	return storedToLeaf(stored), nil
}

func (t *PersistentVectorTree) Load() error {
	stored, err := t.store.GetBranchNode(SetTreeBranchKey(
		t.shardKey,
		t.phaseSet,
		[]int{},
	))
	if err != nil {
		return err
	}

	root, err := t.storedToBranch(stored)
	if err != nil {
		return err
	}

	t.tree.Root = root
	return nil
}

func (t *PersistentVectorTree) trackNodeChanges(
	oldPrefix, newPrefix []int,
	oldNode, newNode crypto.VectorCommitmentNode,
) {
	if oldNode == nil && newNode == nil {
		return
	}

	// deletions first
	if oldNode != nil {
		var oldID NodeID
		switch n := oldNode.(type) {
		case *crypto.VectorCommitmentBranchNode:
			oldID = SetTreeBranchKey(
				t.shardKey,
				t.phaseSet,
				oldPrefix,
			)
		case *crypto.VectorCommitmentLeafNode:
			oldID = SetTreeLeafKey(
				t.shardKey,
				t.phaseSet,
				n.Key,
			)
		}

		if _, ok := t.addedBranches[oldID]; ok {
			delete(t.addedBranches, oldID)
		} else if _, ok := t.addedLeaves[oldID]; ok {
			delete(t.addedLeaves, oldID)
		} else {
			t.deletions[oldID] = struct{}{}
		}
	}

	// then additions
	if newNode != nil {
		switch n := newNode.(type) {
		case *crypto.VectorCommitmentBranchNode:
			id := SetTreeBranchKey(
				t.shardKey,
				t.phaseSet,
				newPrefix,
			)
			t.addedBranches[id] = branchToStored(
				t.shardKey,
				t.phaseSet,
				newPrefix,
				n,
			)
		case *crypto.VectorCommitmentLeafNode:
			id := SetTreeLeafKey(
				t.shardKey,
				t.phaseSet,
				n.Key,
			)
			t.addedLeaves[id] = leafToStored(n)
		}
	}
}

func (t *PersistentVectorTree) Get(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("empty key not allowed")
	}

	var get func(
		prefix []int,
		node crypto.VectorCommitmentNode,
		depth int,
	) ([]byte, error)

	get = func(
		prefix []int,
		node crypto.VectorCommitmentNode,
		depth int,
	) ([]byte, error) {
		if node == nil {
			return nil, nil
		}

		switch n := node.(type) {
		case *crypto.VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				return n.Value, nil
			}
			return nil, nil

		case *crypto.VectorCommitmentBranchNode:
			// Check prefix match
			for i, expectedNibble := range n.Prefix {
				if crypto.GetNextNibble(
					key,
					depth+i*crypto.BranchBits,
				) != expectedNibble {
					return nil, nil
				}
			}
			// Get final nibble after prefix
			finalNibble := crypto.GetNextNibble(
				key,
				depth+len(n.Prefix)*crypto.BranchBits,
			)

			isLoaded := false
			for _, c := range n.Children {
				if c != nil {
					isLoaded = true
					break
				}
			}

			if !isLoaded {
				var self *crypto.VectorCommitmentBranchNode
				var err error

				if len(prefix) == 0 {
					self, err = t.loadBranchNode(
						SetTreeBranchKey(
							t.shardKey,
							t.phaseSet,
							append([]int{}, prefix...),
						),
					)
				} else {
					self, err = t.loadBranchNode(
						SetTreeBranchKey(
							t.shardKey,
							t.phaseSet,
							append(
								append([]int{}, prefix...),
								n.Prefix...,
							),
						),
					)
				}

				if err != nil {
					return nil, errors.Wrap(err, "get")
				}
				n.Children = self.Children
			}
			return get(
				append(
					append(
						append([]int{}, prefix...),
						n.Prefix...,
					),
					finalNibble,
				),
				n.Children[finalNibble],
				depth+len(n.Prefix)*crypto.BranchBits+crypto.BranchBits,
			)
		}

		return nil, nil
	}

	value, err := get([]int{}, t.tree.Root, 0)
	if err != nil {
		return nil, err
	}

	if value == nil {
		return nil, errors.New("key not found")
	}

	return value, nil
}

func (t *PersistentVectorTree) Insert(
	key, value, hashTarget []byte,
	size *big.Int,
) error {
	if len(key) == 0 {
		return errors.New("empty key not allowed")
	}

	var insert func(
		prefix []int,
		node crypto.VectorCommitmentNode,
		depth int,
	) (crypto.VectorCommitmentNode, error)

	insert = func(
		prefix []int,
		node crypto.VectorCommitmentNode,
		depth int,
	) (crypto.VectorCommitmentNode, error) {
		if node == nil {
			t.trackNodeChanges(
				nil,
				prefix,
				nil,
				&crypto.VectorCommitmentLeafNode{
					Key:        key,
					Value:      value,
					HashTarget: hashTarget,
					Size:       size,
				},
			)
			return &crypto.VectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
			}, nil
		}

		switch n := node.(type) {
		case *crypto.VectorCommitmentLeafNode:
			if bytes.Equal(n.Key, key) {
				n.Value = value
				n.HashTarget = hashTarget
				n.Commitment = nil
				n.Size = size
				t.trackNodeChanges(nil, prefix, nil, n)
				return n, nil
			}

			// Get common prefix nibbles and divergence point
			sharedNibbles, divergeDepth := crypto.GetNibblesUntilDiverge(
				n.Key,
				key,
				depth,
			)

			// Create single branch node with shared prefix
			branch := &crypto.VectorCommitmentBranchNode{
				Prefix:        sharedNibbles,
				LeafCount:     2,
				LongestBranch: 1,
				Size:          new(big.Int).Add(n.Size, size),
			}

			// Add both leaves at their final positions
			finalOldNibble := crypto.GetNextNibble(n.Key, divergeDepth)
			finalNewNibble := crypto.GetNextNibble(key, divergeDepth)
			branch.Children[finalOldNibble] = n
			branch.Children[finalNewNibble] = &crypto.VectorCommitmentLeafNode{
				Key:        key,
				Value:      value,
				HashTarget: hashTarget,
				Size:       size,
			}
			t.trackNodeChanges(
				nil,
				append(append(append([]int{}, prefix...), sharedNibbles...), finalOldNibble),
				nil,
				n,
			)
			t.trackNodeChanges(
				nil,
				append(append(append([]int{}, prefix...), sharedNibbles...), finalNewNibble),
				nil,
				&crypto.VectorCommitmentLeafNode{
					Key:        key,
					Value:      value,
					HashTarget: hashTarget,
					Size:       size,
				},
			)
			t.trackNodeChanges(
				nil,
				prefix,
				nil,
				branch,
			)
			return branch, nil

		case *crypto.VectorCommitmentBranchNode:
			isLoaded := false
			for _, c := range n.Children {
				if c != nil {
					isLoaded = true
					break
				}
			}

			if !isLoaded {
				self, err := t.loadBranchNode(
					SetTreeBranchKey(
						t.shardKey,
						t.phaseSet,
						append(
							append([]int{}, prefix...),
							n.Prefix...,
						),
					),
				)
				if err != nil {
					return nil, errors.Wrap(err, "insert")
				}
				n.Children = self.Children
			}

			if len(n.Prefix) > 0 {
				// Check if the new key matches the prefix
				for i, expectedNibble := range n.Prefix {
					actualNibble := crypto.GetNextNibble(key, depth+i*crypto.BranchBits)
					if actualNibble != expectedNibble {
						// Create new branch with shared prefix subset
						newBranch := &crypto.VectorCommitmentBranchNode{
							Prefix:        n.Prefix[:i],
							LeafCount:     n.LeafCount + 1,
							LongestBranch: n.LongestBranch + 1,
							Size:          new(big.Int).Add(n.Size, size),
						}
						// Position old branch and new leaf
						newBranch.Children[expectedNibble] = n
						n.Prefix = n.Prefix[i+1:] // remove shared prefix from old branch
						newBranch.Children[actualNibble] = &crypto.VectorCommitmentLeafNode{
							Key:        key,
							Value:      value,
							HashTarget: hashTarget,
							Size:       size,
						}

						t.trackNodeChanges(
							prefix,
							append(append(append([]int{}, prefix...), newBranch.Prefix...), expectedNibble),
							n,
							n,
						)
						t.trackNodeChanges(
							nil,
							append(append(append([]int{}, prefix...), newBranch.Prefix...), actualNibble),
							nil,
							&crypto.VectorCommitmentLeafNode{
								Key:        key,
								Value:      value,
								HashTarget: hashTarget,
								Size:       size,
							},
						)
						t.trackNodeChanges(
							nil,
							prefix,
							nil,
							newBranch,
						)
						return newBranch, nil
					}
				}

				// Key matches prefix, continue with final nibble
				finalNibble := crypto.GetNextNibble(
					key,
					depth+len(n.Prefix)*crypto.BranchBits,
				)
				inserted, err := insert(
					append(
						append(
							append([]int{}, prefix...),
							n.Prefix...,
						),
						finalNibble,
					),
					n.Children[finalNibble],
					depth+len(n.Prefix)*crypto.BranchBits+crypto.BranchBits,
				)
				if err != nil {
					return nil, err
				}
				n.Children[finalNibble] = inserted
				n.Commitment = nil
				n.LeafCount += 1
				switch i := inserted.(type) {
				case *crypto.VectorCommitmentBranchNode:
					if n.LongestBranch <= i.LongestBranch {
						n.LongestBranch = i.LongestBranch + 1
					}
				case *crypto.VectorCommitmentLeafNode:
					n.LongestBranch = 1
				}
				n.Size = n.Size.Add(n.Size, size)

				t.trackNodeChanges(
					nil,
					prefix,
					nil,
					n,
				)
				return n, nil
			} else {
				// Simple branch without prefix
				nibble := crypto.GetNextNibble(key, depth)
				inserted, err := insert(
					append(
						append(
							append([]int{}, prefix...),
							n.Prefix...,
						),
						nibble,
					),
					n.Children[nibble],
					depth+crypto.BranchBits,
				)
				if err != nil {
					return nil, err
				}
				n.Children[nibble] = inserted
				n.Commitment = nil
				n.LeafCount += 1
				switch i := inserted.(type) {
				case *crypto.VectorCommitmentBranchNode:
					if n.LongestBranch <= i.LongestBranch {
						n.LongestBranch = i.LongestBranch + 1
					}
				case *crypto.VectorCommitmentLeafNode:
					n.LongestBranch = 1
				}
				n.Size = n.Size.Add(n.Size, size)

				t.trackNodeChanges(
					nil,
					prefix,
					nil,
					n,
				)
				return n, nil
			}
		}

		return nil, nil
	}

	newRoot, err := insert([]int{}, t.tree.Root, 0)
	if err != nil {
		return err
	}

	t.tree.Root = newRoot

	return nil
}

func (t *PersistentVectorTree) Delete(key []byte) error {
	return errors.New("deletion not supported")
}

func (t *PersistentVectorTree) Commit(recalculate bool) []byte {
	return t.tree.Commit(recalculate)
}

func (t *PersistentVectorTree) WriteBatch(txn Transaction) error {
	err := t.store.BatchWrite(txn, t.addedBranches, t.addedLeaves, t.deletions)
	if err != nil {
		return errors.Wrap(err, "write batch")
	}

	// Reset change tracking
	t.addedBranches = make(map[NodeID]*StoredBranchNode)
	t.addedLeaves = make(map[NodeID]*StoredLeafNode)
	t.deletions = make(map[NodeID]struct{})

	return nil
}

func (t *PersistentVectorTree) GetMetadata() (
	leafCount int,
	longestBranch int,
) {
	return t.tree.GetMetadata()
}

func (t *PersistentVectorTree) GetSize() *big.Int {
	return t.tree.GetSize()
}

func (t *PersistentVectorTree) Prove(key []byte) [][]byte {
	return t.tree.Prove(key)
}

func (t *PersistentVectorTree) Verify(key []byte, proofs [][]byte) bool {
	return t.tree.Verify(key, proofs)
}

func (
	t *PersistentVectorTree,
) GetInternalTree() *crypto.RawVectorCommitmentTree {
	return t.tree
}

// this method is truncating the ints to bytes because the total size of the
// branch bits is 6. if this ever increases, this will break a lot of things.
func packNibbles(values []int) []byte {
	out := []byte{}
	for _, v := range values {
		out = append(out, byte(v))
	}
	return out
}
