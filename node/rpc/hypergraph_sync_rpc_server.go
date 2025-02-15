package rpc

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	hypergraph "source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

// hypergraphComparisonServer implements the bidirectional sync service.
type hypergraphComparisonServer struct {
	protobufs.UnimplementedHypergraphComparisonServiceServer

	logger               *zap.Logger
	localHypergraphStore store.HypergraphStore
	localHypergraph      *hypergraph.Hypergraph
}

func NewHypergraphComparisonServer(
	logger *zap.Logger,
	hypergraphStore store.HypergraphStore,
	hypergraph *hypergraph.Hypergraph,
) *hypergraphComparisonServer {
	return &hypergraphComparisonServer{
		logger:               logger,
		localHypergraphStore: hypergraphStore,
		localHypergraph:      hypergraph,
	}
}

// sendLeafData builds a LeafData message (with the full leaf data) for the
// node at the given path in the local tree and sends it over the stream.
func sendLeafData(
	stream protobufs.HypergraphComparisonService_HyperStreamClient,
	hypergraphStore store.HypergraphStore,
	localTree *crypto.VectorCommitmentTree,
	path []int32,
	metadataOnly bool,
) error {
	send := func(leaf *crypto.VectorCommitmentLeafNode) error {
		update := &protobufs.LeafData{
			Key:        leaf.Key,
			Value:      leaf.Value,
			HashTarget: leaf.HashTarget,
			Size:       leaf.Size.FillBytes(make([]byte, 32)),
		}
		if !metadataOnly {
			tree, err := hypergraphStore.LoadVertexTree(leaf.Key)
			if err == nil {
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				if err := enc.Encode(tree); err != nil {
					return errors.Wrap(err, "send leaf data")
				}
				update.UnderlyingData = buf.Bytes()
			}
		}
		msg := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_LeafData{
				LeafData: update,
			},
		}
		return stream.Send(msg)
	}

	node := getNodeAtPath(localTree.Root, path, 0)
	leaf, ok := node.(*crypto.VectorCommitmentLeafNode)
	if !ok {
		children := crypto.GetAllLeaves(node)
		for _, child := range children {
			if child == nil {
				continue
			}

			if err := send(child); err != nil {
				return err
			}
		}

		return nil
	}

	return send(leaf)
}

// equalBytes compares two byte slices for equality.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// getNodeAtPath traverses the tree along the provided nibble path. It returns
// the node found (or nil if not found). The depth argument is used for internal
// recursion.
func getNodeAtPath(
	node crypto.VectorCommitmentNode,
	path []int32,
	depth int,
) crypto.VectorCommitmentNode {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		return node
	}

	switch n := node.(type) {
	case *crypto.VectorCommitmentLeafNode:
		return node
	case *crypto.VectorCommitmentBranchNode:
		// Check that the branch's prefix matches the beginning of the query path.
		if len(path) < len(n.Prefix) {
			return nil
		}

		for i, nib := range n.Prefix {
			if int32(nib) != path[i] {
				return nil
			}
		}

		// Remove the prefix portion from the path.
		remainder := path[len(n.Prefix):]
		if len(remainder) == 0 {
			return node
		}

		// The first element of the remainder selects the child.
		childIndex := remainder[0]
		if int(childIndex) < 0 || int(childIndex) >= len(n.Children) {
			return nil
		}

		child := n.Children[childIndex]
		if child == nil {
			return nil
		}

		return getNodeAtPath(child, remainder[1:], depth+len(n.Prefix)+1)
	}
	return nil
}

// getBranchInfoFromTree looks up the node at the given path in the local tree,
// computes its commitment, and (if it is a branch) collects its immediate
// children's commitments.
func getBranchInfoFromTree(tree *crypto.VectorCommitmentTree, path []int32) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	node := getNodeAtPath(tree.Root, path, 0)
	if node == nil {
		return nil, fmt.Errorf("node not found at path %v", path)
	}

	commitment := node.Commit(false)
	branchInfo := &protobufs.HypergraphComparisonResponse{
		Path:       path,
		Commitment: commitment,
	}

	if branch, ok := node.(*crypto.VectorCommitmentBranchNode); ok {
		for _, p := range branch.Prefix {
			branchInfo.Path = append(branchInfo.Path, int32(p))
		}
		for i := 0; i < len(branch.Children); i++ {
			if branch.Children[i] != nil {
				childCommit := branch.Children[i].Commit(false)
				branchInfo.Children = append(
					branchInfo.Children,
					&protobufs.BranchChild{
						Index:      int32(i),
						Commitment: childCommit,
					},
				)
			}
		}
	}
	return branchInfo, nil
}

// isLeaf infers whether a HypergraphComparisonResponse message represents a
// leaf node.
func isLeaf(info *protobufs.HypergraphComparisonResponse) bool {
	return len(info.Children) == 0
}

// sendLeafDataServer builds a LeafData message from the local tree (for the
// node at the given path) and sends it over the server-side stream.
func sendLeafDataServer(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
	hypergraphStore store.HypergraphStore,
	localTree *crypto.VectorCommitmentTree,
	path []int32,
	metadataOnly bool,
) error {
	send := func(leaf *crypto.VectorCommitmentLeafNode) error {
		update := &protobufs.LeafData{
			Key:        leaf.Key,
			Value:      leaf.Value,
			HashTarget: leaf.HashTarget,
			Size:       leaf.Size.FillBytes(make([]byte, 32)),
		}
		if !metadataOnly {
			tree, err := hypergraphStore.LoadVertexTree(leaf.Key)
			if err == nil {
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				if err := enc.Encode(tree); err != nil {
					return errors.Wrap(err, "send leaf data")
				}
				update.UnderlyingData = buf.Bytes()
			}
		}
		msg := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_LeafData{
				LeafData: update,
			},
		}
		return stream.Send(msg)
	}

	node := getNodeAtPath(localTree.Root, path, 0)
	leaf, ok := node.(*crypto.VectorCommitmentLeafNode)
	if !ok {
		children := crypto.GetAllLeaves(node)
		for _, child := range children {
			if child == nil {
				continue
			}

			if err := send(child); err != nil {
				return err
			}
		}

		return nil
	}

	return send(leaf)
}

// syncTreeBidirectionallyServer implements the diff and sync logic on the
// server side. It sends the local root info, then processes incoming messages,
// and queues further queries as differences are detected.
func syncTreeBidirectionallyServer(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
	logger *zap.Logger,
	localHypergraphStore store.HypergraphStore,
	localHypergraph *hypergraph.Hypergraph,
	metadataOnly bool,
) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	query := msg.GetQuery()
	if query == nil {
		return errors.New("client did not send valid initialization message")
	}
	logger.Info(
		"received initialization message",
		zap.String("shard_key", hex.EncodeToString(query.ShardKey)),
		zap.Int("phase_set", int(query.PhaseSet)),
	)

	// Lookup our local phase set.
	var phaseSet map[hypergraph.ShardKey]*hypergraph.IdSet
	switch query.PhaseSet {
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS:
		phaseSet = localHypergraph.GetVertexAdds()
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES:
		phaseSet = localHypergraph.GetVertexRemoves()
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS:
		phaseSet = localHypergraph.GetHyperedgeAdds()
	case protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES:
		phaseSet = localHypergraph.GetHyperedgeRemoves()
	}

	if len(query.ShardKey) != 35 {
		return errors.New("invalid shard key")
	}

	shardKey := hypergraph.ShardKey{
		L1: [3]byte(query.ShardKey[:3]),
		L2: [32]byte(query.ShardKey[3:]),
	}
	idSet, ok := phaseSet[shardKey]
	if !ok {
		return errors.New("server does not have phase set")
	}

	// Send our root branch info.
	rootPath := []int32{}
	rootInfo, err := getBranchInfoFromTree(idSet.GetTree(), rootPath)
	if err != nil {
		return err
	}
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: rootInfo,
		},
	}); err != nil {
		return err
	}

	pendingQueries := make(chan []int32)
	go func(path []int32) {
		pendingQueries <- path
	}(rootPath)

	incoming := make(chan *protobufs.HypergraphComparison, 10000)
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				close(incoming)
				return
			}
			if err != nil {
				close(incoming)
				return
			}
			incoming <- msg
		}
	}()

	for {
		select {
		case path := <-pendingQueries:
			logger.Info(
				"server sending comparison query",
				zap.String("path", hex.EncodeToString(packNibbles(path))),
			)
			queryMsg := &protobufs.HypergraphComparison{
				Payload: &protobufs.HypergraphComparison_Query{
					Query: &protobufs.HypergraphComparisonQuery{
						ShardKey:        query.ShardKey,
						PhaseSet:        query.PhaseSet,
						Path:            path,
						IncludeLeafData: false,
					},
				},
			}
			if err := stream.Send(queryMsg); err != nil {
				return err
			}

		case msg, ok := <-incoming:
			if !ok {
				return nil
			}
			switch payload := msg.Payload.(type) {

			case *protobufs.HypergraphComparison_Response:
				remoteInfo := payload.Response
				logger.Info(
					"server handling response",
					zap.String("path", hex.EncodeToString(packNibbles(remoteInfo.Path))),
				)
				localInfo, err := getBranchInfoFromTree(
					idSet.GetTree(),
					remoteInfo.Path,
				)
				if err != nil {
					logger.Info(
						"server requesting missing node",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(remoteInfo.Path)),
						),
					)
					missingQuery := &protobufs.HypergraphComparison{
						Payload: &protobufs.HypergraphComparison_Query{
							Query: &protobufs.HypergraphComparisonQuery{
								ShardKey:        query.ShardKey,
								PhaseSet:        query.PhaseSet,
								Path:            remoteInfo.Path,
								IncludeLeafData: true,
							},
						},
					}
					if err := stream.Send(missingQuery); err != nil {
						return err
					}
					// Do not queue children for a missing node.
					continue
				}

				if !equalBytes(localInfo.Commitment, remoteInfo.Commitment) {
					logger.Info(
						"server mismatching commitment at path",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(remoteInfo.Path)),
						),
						zap.String("commitment", hex.EncodeToString(remoteInfo.Commitment)),
					)
					if isLeaf(remoteInfo) {
						logger.Info(
							"server sending leaf info",
							zap.String(
								"path",
								hex.EncodeToString(packNibbles(remoteInfo.Path)),
							),
						)
						if err := sendLeafDataServer(
							stream,
							localHypergraphStore,
							idSet.GetTree(),
							remoteInfo.Path,
							metadataOnly,
						); err != nil {
							return err
						}
					} else {
						for _, remoteChild := range remoteInfo.Children {
							var localChildCommit []byte
							for _, localChild := range localInfo.Children {
								if localChild.Index == remoteChild.Index {
									localChildCommit = localChild.Commitment
									break
								}
							}
							if !equalBytes(localChildCommit, remoteChild.Commitment) {
								logger.Info(
									"found mismatching child commitment, enqueueing",
									zap.String(
										"path",
										hex.EncodeToString(packNibbles(remoteInfo.Path)),
									),
									zap.Int32("child_index", remoteChild.Index),
									zap.String(
										"local_commitment",
										hex.EncodeToString(localChildCommit),
									),
									zap.String(
										"remote_commitment",
										hex.EncodeToString(remoteChild.Commitment),
									),
								)
								newPath := append(
									append([]int32(nil), remoteInfo.Path...),
									remoteChild.Index,
								)
								go func(path []int32) {
									pendingQueries <- path
								}(newPath)
							}
						}
					}
				}
			case *protobufs.HypergraphComparison_Query:
				queryPath := payload.Query.Path
				logger.Info(
					"server received query for leaves",
					zap.String(
						"path",
						hex.EncodeToString(packNibbles(queryPath)),
					),
				)
				if payload.Query.IncludeLeafData {
					if err := sendLeafDataServer(
						stream,
						localHypergraphStore,
						idSet.GetTree(),
						queryPath,
						metadataOnly,
					); err != nil {
						return err
					}
				} else {
					logger.Info(
						"server received query for branches",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(queryPath)),
						),
					)
					branchInfo, err := getBranchInfoFromTree(idSet.GetTree(), queryPath)
					if err != nil {
						continue
					}
					resp := &protobufs.HypergraphComparison{
						Payload: &protobufs.HypergraphComparison_Response{
							Response: branchInfo,
						},
					}
					if err := stream.Send(resp); err != nil {
						return err
					}
				}
			case *protobufs.HypergraphComparison_LeafData:
				remoteUpdate := payload.LeafData
				logger.Info(
					"received leaf data",
					zap.String(
						"key",
						hex.EncodeToString(payload.LeafData.Key),
					),
				)
				if len(remoteUpdate.UnderlyingData) != 0 {
					txn, err := localHypergraphStore.NewTransaction(false)
					if err != nil {
						return err
					}
					tree := &crypto.VectorCommitmentTree{}
					var b bytes.Buffer
					b.Write(remoteUpdate.UnderlyingData)

					dec := gob.NewDecoder(&b)
					if err := dec.Decode(tree); err != nil {
						txn.Abort()
						return err
					}
					err = localHypergraphStore.SaveVertexTree(txn, remoteUpdate.Key, tree)
					if err != nil {
						txn.Abort()
						return err
					}

					if err = txn.Commit(); err != nil {
						txn.Abort()
						return err
					}
				}
				idSet.Add(hypergraph.AtomFromBytes(remoteUpdate.Value))
			}
		case <-time.After(5 * time.Second):
			logger.Info("server timed out")
			return nil
		}
	}
}

// HyperStream is the gRPC method that handles bidirectional synchronization.
func (s *hypergraphComparisonServer) HyperStream(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
) error {
	return syncTreeBidirectionallyServer(
		stream,
		s.logger,
		s.localHypergraphStore,
		s.localHypergraph,
		false,
	)
}

// SyncTreeBidirectionally performs the tree diff and synchronization.
// The caller (e.g. the client) must initiate the diff from its root.
// After that, both sides exchange queries, branch info, and leaf updates until
// their local trees are synchronized.
func SyncTreeBidirectionally(
	stream protobufs.HypergraphComparisonService_HyperStreamClient,
	logger *zap.Logger,
	shardKey []byte,
	phaseSet protobufs.HypergraphPhaseSet,
	hypergraphStore store.HypergraphStore,
	localTree *crypto.VectorCommitmentTree,
	metadataOnly bool,
) error {
	logger.Info(
		"sending initialization message",
		zap.String("shard_key", hex.EncodeToString(shardKey)),
		zap.Int("phase_set", int(phaseSet)),
	)
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				ShardKey:        shardKey,
				PhaseSet:        phaseSet,
				Path:            []int32{},
				Commitment:      localTree.Commit(false),
				IncludeLeafData: false,
			},
		},
	}); err != nil {
		return err
	}

	rootPath := []int32{}
	rootInfo, err := getBranchInfoFromTree(localTree, rootPath)
	if err != nil {
		return err
	}
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: rootInfo,
		},
	}); err != nil {
		return err
	}

	pendingQueries := make(chan []int32)
	go func(path []int32) {
		pendingQueries <- path
	}([]int32{})

	incoming := make(chan *protobufs.HypergraphComparison, 10000)
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				close(incoming)
				return
			}
			if err != nil {
				close(incoming)
				return
			}
			incoming <- msg
		}
	}()

	for {
		select {
		case path := <-pendingQueries:
			logger.Info(
				"sending comparison query",
				zap.String("path", hex.EncodeToString(packNibbles(path))),
			)
			queryMsg := &protobufs.HypergraphComparison{
				Payload: &protobufs.HypergraphComparison_Query{
					Query: &protobufs.HypergraphComparisonQuery{
						Path:            path,
						IncludeLeafData: false,
					},
				},
			}
			if err := stream.Send(queryMsg); err != nil {
				return err
			}
		case msg, ok := <-incoming:
			if !ok {
				return nil
			}
			switch payload := msg.Payload.(type) {
			case *protobufs.HypergraphComparison_Response:
				remoteInfo := payload.Response
				logger.Info(
					"handling response",
					zap.String("path", hex.EncodeToString(packNibbles(remoteInfo.Path))),
				)
				localInfo, err := getBranchInfoFromTree(localTree, remoteInfo.Path)
				if err != nil {
					logger.Info(
						"requesting missing node",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(remoteInfo.Path)),
						),
					)
					missingQuery := &protobufs.HypergraphComparison{
						Payload: &protobufs.HypergraphComparison_Query{
							Query: &protobufs.HypergraphComparisonQuery{
								Path:            remoteInfo.Path,
								IncludeLeafData: true,
							},
						},
					}
					if err := stream.Send(missingQuery); err != nil {
						return err
					}
					continue
				}
				if !equalBytes(localInfo.Commitment, remoteInfo.Commitment) {
					logger.Info(
						"mismatching commitment at path",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(remoteInfo.Path)),
						),
						zap.String("commitment", hex.EncodeToString(remoteInfo.Commitment)),
					)
					if isLeaf(remoteInfo) {
						logger.Info(
							"sending leaf info",
							zap.String(
								"path",
								hex.EncodeToString(packNibbles(remoteInfo.Path)),
							),
						)
						if err := sendLeafData(
							stream,
							hypergraphStore,
							localTree,
							remoteInfo.Path,
							metadataOnly,
						); err != nil {
							return err
						}
					} else {
						for _, remoteChild := range remoteInfo.Children {
							var localChildCommit []byte
							for _, localChild := range localInfo.Children {
								if localChild.Index == remoteChild.Index {
									localChildCommit = localChild.Commitment
									break
								}
							}
							if !equalBytes(localChildCommit, remoteChild.Commitment) {
								logger.Info(
									"found mismatching child commitment, enqueueing",
									zap.String(
										"path",
										hex.EncodeToString(packNibbles(remoteInfo.Path)),
									),
									zap.Int32("child_index", remoteChild.Index),
									zap.String(
										"local_commitment",
										hex.EncodeToString(localChildCommit),
									),
									zap.String(
										"remote_commitment",
										hex.EncodeToString(remoteChild.Commitment),
									),
								)
								newPath := append(
									append([]int32(nil), remoteInfo.Path...),
									remoteChild.Index,
								)
								go func(path []int32) {
									pendingQueries <- path
								}(newPath)
							}
						}
					}
				}
			case *protobufs.HypergraphComparison_Query:
				queryPath := payload.Query.Path
				if payload.Query.IncludeLeafData {
					logger.Info(
						"received query for leaves",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(queryPath)),
						),
					)
					if err := sendLeafData(
						stream,
						hypergraphStore,
						localTree,
						queryPath,
						metadataOnly,
					); err != nil {
						return err
					}
				} else {
					logger.Info(
						"received query for branches",
						zap.String(
							"path",
							hex.EncodeToString(packNibbles(queryPath)),
						),
					)
					branchInfo, err := getBranchInfoFromTree(localTree, queryPath)
					if err != nil {
						continue
					}
					resp := &protobufs.HypergraphComparison{
						Payload: &protobufs.HypergraphComparison_Response{
							Response: branchInfo,
						},
					}
					if err := stream.Send(resp); err != nil {
						return err
					}
				}
			case *protobufs.HypergraphComparison_LeafData:
				logger.Info(
					"received leaf data",
					zap.String(
						"key",
						hex.EncodeToString(payload.LeafData.Key),
					),
				)
				remoteUpdate := payload.LeafData
				size := new(big.Int).SetBytes(remoteUpdate.Size)
				if len(remoteUpdate.UnderlyingData) != 0 {
					txn, err := hypergraphStore.NewTransaction(false)
					if err != nil {
						return err
					}
					tree := &crypto.VectorCommitmentTree{}
					var b bytes.Buffer
					b.Write(remoteUpdate.UnderlyingData)

					dec := gob.NewDecoder(&b)
					if err := dec.Decode(tree); err != nil {
						txn.Abort()
						return err
					}
					err = hypergraphStore.SaveVertexTree(txn, remoteUpdate.Key, tree)
					if err != nil {
						txn.Abort()
						return err
					}

					if err = txn.Commit(); err != nil {
						txn.Abort()
						return err
					}
				}

				localTree.Insert(
					remoteUpdate.Key,
					remoteUpdate.Value,
					remoteUpdate.HashTarget,
					size,
				)
			}
		case <-time.After(5 * time.Second):
			logger.Info("timed out")
			return nil
		}
	}
}

func packNibbles(values []int32) []byte {
	totalBits := len(values) * 6
	out := make([]byte, (totalBits+7)/8)
	bitOffset := 0

	for _, v := range values {
		bitsRemaining := 6
		for bitsRemaining > 0 {
			byteIndex := bitOffset / 8
			bitPos := bitOffset % 8
			bitsAvailable := 8 - bitPos
			n := bitsRemaining
			if n > bitsAvailable {
				n = bitsAvailable
			}

			// From the current 6-bit value, take the top n bits that haven't been
			// written.
			shift := bitsRemaining - n
			bitsToWrite := int((v >> shift) & ((1 << n) - 1))

			// Place these bits in the current byte. Since we fill each byte from the
			// most-significant bit down, shift them to the proper position.
			shiftPos := bitsAvailable - n
			out[byteIndex] |= byte(bitsToWrite << shiftPos)

			bitOffset += n
			bitsRemaining -= n
		}
	}
	return out
}
