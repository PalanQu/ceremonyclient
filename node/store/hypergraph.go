package store

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
)

type HypergraphStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	LoadVertexTree(id []byte) (
		*crypto.VectorCommitmentTree,
		error,
	)
	LoadVertexData(id []byte) ([]application.Encrypted, error)
	SaveVertexTree(
		txn Transaction,
		id []byte,
		vertTree *crypto.VectorCommitmentTree,
	) error
	CommitAndSaveVertexData(
		txn Transaction,
		id []byte,
		data []application.Encrypted,
	) (*crypto.VectorCommitmentTree, []byte, error)
	LoadHypergraph() (
		*application.Hypergraph,
		error,
	)
	SaveHypergraph(
		hg *application.Hypergraph,
	) error
}

var _ HypergraphStore = (*PebbleHypergraphStore)(nil)

type PebbleHypergraphStore struct {
	config *config.DBConfig
	db     KVDB
	logger *zap.Logger
}

func NewPebbleHypergraphStore(
	config *config.DBConfig,
	db KVDB,
	logger *zap.Logger,
) *PebbleHypergraphStore {
	return &PebbleHypergraphStore{
		config,
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
		L1: [3]byte(key[2:5]),
		L2: [32]byte(key[5:]),
	}
}

func (p *PebbleHypergraphStore) NewTransaction(indexed bool) (
	Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleHypergraphStore) LoadVertexTree(id []byte) (
	*crypto.VectorCommitmentTree,
	error,
) {
	tree := &crypto.VectorCommitmentTree{}
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
	tree := &crypto.VectorCommitmentTree{}
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
	vertTree *crypto.VectorCommitmentTree,
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
) (*crypto.VectorCommitmentTree, []byte, error) {
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
	hg := application.NewHypergraph()
	hypergraphDir := path.Join(p.config.Path, "hypergraph")

	vertexAddsPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS},
	)
	vertexRemovesPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES},
	)
	hyperedgeAddsPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS},
	)
	hyperedgeRemovesPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES},
	)

	return hg, errors.Wrap(
		filepath.WalkDir(
			hypergraphDir,
			func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				shardSet, err := hex.DecodeString(d.Name())
				if err != nil {
					return err
				}

				var atomType application.AtomType
				var setType application.PhaseType

				if strings.HasPrefix(d.Name(), vertexAddsPrefix) {
					atomType = application.VertexAtomType
					setType = application.AddsPhaseType
				} else if strings.HasPrefix(d.Name(), vertexRemovesPrefix) {
					atomType = application.VertexAtomType
					setType = application.RemovesPhaseType
				} else if strings.HasPrefix(d.Name(), hyperedgeAddsPrefix) {
					atomType = application.HyperedgeAtomType
					setType = application.AddsPhaseType
				} else if strings.HasPrefix(d.Name(), hyperedgeRemovesPrefix) {
					atomType = application.HyperedgeAtomType
					setType = application.RemovesPhaseType
				}

				fileBytes, err := os.ReadFile(p)
				if err != nil {
					return err
				}

				err = hg.ImportFromBytes(
					atomType,
					setType,
					shardKeyFromKey(shardSet),
					fileBytes,
				)
				if err != nil {
					return err
				}

				return nil
			},
		),
		"load hypergraph",
	)
}

func (p *PebbleHypergraphStore) SaveHypergraph(
	hg *application.Hypergraph,
) error {
	hypergraphDir := path.Join(p.config.Path, "hypergraph")
	if _, err := os.Stat(hypergraphDir); os.IsNotExist(err) {
		err := os.MkdirAll(hypergraphDir, 0777)
		if err != nil {
			return errors.Wrap(err, "save hypergraph")
		}
	}

	for shardKey, vertexAdds := range hg.GetVertexAdds() {
		if vertexAdds.IsDirty() {
			err := os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexAddsKey(shardKey)),
				),
				vertexAdds.ToBytes(),
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, vertexRemoves := range hg.GetVertexRemoves() {
		if vertexRemoves.IsDirty() {
			err := os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexRemovesKey(shardKey)),
				),
				vertexRemoves.ToBytes(),
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, hyperedgeAdds := range hg.GetHyperedgeAdds() {
		if hyperedgeAdds.IsDirty() {
			err := os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeAddsKey(shardKey)),
				),
				hyperedgeAdds.ToBytes(),
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, hyperedgeRemoves := range hg.GetHyperedgeRemoves() {
		if hyperedgeRemoves.IsDirty() {
			err := os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeRemovesKey(shardKey)),
				),
				hyperedgeRemoves.ToBytes(),
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	return nil
}
