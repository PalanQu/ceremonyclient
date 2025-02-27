package rpc

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	hypergraph "source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type SyncController struct {
	isSyncing atomic.Bool
}

func (s *SyncController) TryEstablishSyncSession() bool {
	return !s.isSyncing.Swap(true)
}

func (s *SyncController) EndSyncSession() {
	s.isSyncing.Store(false)
}

func NewSyncController() *SyncController {
	return &SyncController{
		isSyncing: atomic.Bool{},
	}
}

// hypergraphComparisonServer implements the bidirectional sync service.
type hypergraphComparisonServer struct {
	protobufs.UnimplementedHypergraphComparisonServiceServer

	logger               *zap.Logger
	localHypergraphStore store.HypergraphStore
	localHypergraph      *hypergraph.Hypergraph
	syncController       *SyncController
	debugTotalCoins      int
}

func NewHypergraphComparisonServer(
	logger *zap.Logger,
	hypergraphStore store.HypergraphStore,
	hypergraph *hypergraph.Hypergraph,
	syncController *SyncController,
	debugTotalCoins int,
) *hypergraphComparisonServer {
	return &hypergraphComparisonServer{
		logger:               logger,
		localHypergraphStore: hypergraphStore,
		localHypergraph:      hypergraph,
		syncController:       syncController,
		debugTotalCoins:      debugTotalCoins,
	}
}

// sendLeafData builds a LeafData message (with the full leaf data) for the
// node at the given path in the local tree and sends it over the stream.
func sendLeafData(
	stream HyperStream,
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
		IsRoot:     len(path) == 0,
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

func queryNext(
	ctx context.Context,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	stream HyperStream,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				Path:            path,
				IncludeLeafData: false,
			},
		},
	}); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query",
		)
	case resp, ok := <-incomingResponses:
		if !ok {
			return nil, errors.Wrap(
				errors.New("channel closed"),
				"handle query",
			)
		}
		return resp, nil
	case <-time.After(5 * time.Second):
		return nil, errors.Wrap(
			errors.New("timed out"),
			"handle query",
		)
	}
}

func handleQueryNext(
	ctx context.Context,
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	stream HyperStream,
	localTree *crypto.VectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	select {
	case <-ctx.Done():
		return nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query next",
		)
	case query, ok := <-incomingQueries:
		if !ok {
			return nil, errors.Wrap(
				errors.New("channel closed"),
				"handle query next",
			)
		}

		if slices.Compare(query.Path, path) != 0 {
			return nil, errors.Wrap(
				errors.New("invalid query received"),
				"handle query next",
			)
		}

		branchInfo, err := getBranchInfoFromTree(localTree, path)
		if err != nil {
			return nil, errors.Wrap(err, "handle query next")
		}

		resp := &protobufs.HypergraphComparison{
			Payload: &protobufs.HypergraphComparison_Response{
				Response: branchInfo,
			},
		}

		if err := stream.Send(resp); err != nil {
			return nil, errors.Wrap(err, "handle query next")
		}

		return branchInfo, nil
	case <-time.After(5 * time.Second):
		return nil, errors.Wrap(
			errors.New("timed out"),
			"handle query next",
		)
	}
}

func descendIndex(
	ctx context.Context,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	stream HyperStream,
	localTree *crypto.VectorCommitmentTree,
	path []int32,
) (
	*protobufs.HypergraphComparisonResponse,
	*protobufs.HypergraphComparisonResponse,
	error,
) {
	branchInfo, err := getBranchInfoFromTree(localTree, path)
	if err != nil {
		return nil, nil, errors.Wrap(err, "descend index")
	}

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := stream.Send(resp); err != nil {
		return nil, nil, errors.Wrap(err, "descend index")
	}

	select {
	case <-ctx.Done():
		return nil, nil, errors.Wrap(
			errors.New("context canceled"),
			"handle query next",
		)
	case resp, ok := <-incomingResponses:
		if !ok {
			return nil, nil, errors.Wrap(
				errors.New("channel closed"),
				"descend index",
			)
		}

		if slices.Compare(branchInfo.Path, resp.Path) != 0 {
			return nil, nil, errors.Wrap(
				fmt.Errorf(
					"invalid path received: %v, expected: %v",
					resp.Path,
					branchInfo.Path,
				),
				"descend index",
			)
		}

		return branchInfo, resp, nil
	case <-time.After(5 * time.Second):
		return nil, nil, errors.Wrap(
			errors.New("timed out"),
			"descend index",
		)
	}
}

type HyperStream interface {
	Send(*protobufs.HypergraphComparison) error
	Recv() (*protobufs.HypergraphComparison, error)
}

func walk(
	ctx context.Context,
	logger *zap.Logger,
	path []int32,
	lnode, rnode *protobufs.HypergraphComparisonResponse,
	incomingQueries <-chan *protobufs.HypergraphComparisonQuery,
	incomingResponses <-chan *protobufs.HypergraphComparisonResponse,
	stream HyperStream,
	hypergraphStore store.HypergraphStore,
	localTree *crypto.VectorCommitmentTree,
	metadataOnly bool,
) error {
	select {
	case <-ctx.Done():
		return errors.New("context canceled")
	default:
	}

	if isLeaf(lnode) && isLeaf(rnode) {
		if !bytes.Equal(lnode.Commitment, rnode.Commitment) {
			logger.Info("leaves mismatch commitments, sending")
			sendLeafData(
				stream,
				hypergraphStore,
				localTree,
				path,
				metadataOnly,
			)
		}
		return nil
	}

	if isLeaf(rnode) || isLeaf(lnode) {
		logger.Info("leaf/branch mismatch at path")
		sendLeafData(
			stream,
			hypergraphStore,
			localTree,
			path,
			metadataOnly,
		)
		return nil
	}

	lpref := lnode.Path
	rpref := rnode.Path
	if len(lpref) != len(rpref) {
		logger.Info(
			"prefix length mismatch",
			zap.Int("local_prefix", len(lpref)),
			zap.Int("remote_prefix", len(rpref)),
		)
		if len(lpref) > len(rpref) {
			logger.Info("local prefix longer, traversing remote to path")
			traverse := lpref[len(rpref)-1:]
			rtrav := rnode
			traversePath := append([]int32{}, rpref...)
			for _, nibble := range traverse {
				logger.Info("attempting remote traversal step")
				for _, child := range rtrav.Children {
					if child.Index == nibble {
						logger.Info("sending query")
						traversePath = append(traversePath, child.Index)
						var err error
						rtrav, err = queryNext(
							ctx,
							incomingResponses,
							stream,
							traversePath,
						)
						if err != nil {
							logger.Error("query failed", zap.Error(err))
							return errors.Wrap(err, "walk")
						}

						if rtrav == nil {
							logger.Info("traversal could not reach path, sending leaf data")
							sendLeafData(
								stream,
								hypergraphStore,
								localTree,
								path,
								metadataOnly,
							)
							return nil
						}
					}
				}
			}
			logger.Info("traversal completed, performing walk")
			return walk(
				ctx,
				logger,
				path,
				lnode,
				rtrav,
				incomingQueries,
				incomingResponses,
				stream,
				hypergraphStore,
				localTree,
				metadataOnly,
			)
		} else {
			logger.Info("remote prefix longer, traversing local to path")
			traverse := rpref[len(lpref)-1:]
			ltrav := lnode
			traversedPath := append([]int32{}, lnode.Path...)

			for _, nibble := range traverse {
				logger.Info("attempting local traversal step")
				preTraversal := append([]int32{}, traversedPath...)
				for _, child := range ltrav.Children {
					if child.Index == nibble {
						traversedPath = append(traversedPath, nibble)
						var err error
						logger.Info("expecting query")
						ltrav, err = handleQueryNext(
							ctx,
							incomingQueries,
							stream,
							localTree,
							traversedPath,
						)
						if err != nil {
							logger.Error("expect failed", zap.Error(err))
							return errors.Wrap(err, "walk")
						}

						if ltrav == nil {
							logger.Info("traversal could not reach path, sending leaf data")
							sendLeafData(
								stream,
								hypergraphStore,
								localTree,
								path,
								metadataOnly,
							)
							return nil
						}
					} else {
						logger.Info("sending leaves of known missing branch")
						sendLeafData(
							stream,
							hypergraphStore,
							localTree,
							append(append([]int32{}, preTraversal...), child.Index),
							metadataOnly,
						)
					}
				}
			}
			logger.Info("traversal completed, performing walk")
			return walk(
				ctx,
				logger,
				path,
				ltrav,
				rnode,
				incomingQueries,
				incomingResponses,
				stream,
				hypergraphStore,
				localTree,
				metadataOnly,
			)
		}
	} else {
		logger.Info(
			"prefix match length, compare",
			zap.Int("local_prefix", len(lpref)),
			zap.Int("remote_prefix", len(rpref)),
		)
		if slices.Compare(lpref, rpref) == 0 {
			logger.Info("prefixes match, diffing children")
			for i := int32(0); i < 64; i++ {
				logger.Info("checking branch", zap.Int32("branch", i))
				var lchild *protobufs.BranchChild = nil
				for _, lc := range lnode.Children {
					if lc.Index == i {
						logger.Info("local instance found", zap.Int32("branch", i))

						lchild = lc
						break
					}
				}
				var rchild *protobufs.BranchChild = nil
				for _, rc := range rnode.Children {
					if rc.Index == i {
						logger.Info("remote instance found", zap.Int32("branch", i))

						rchild = rc
						break
					}
				}
				if (lchild != nil && rchild == nil) ||
					(lchild == nil && rchild != nil) {
					logger.Info("branch divergence")
					sendLeafData(stream, hypergraphStore, localTree, path, metadataOnly)
				} else {
					if lchild != nil {
						nextPath := append(
							append([]int32{}, lpref...),
							lchild.Index,
						)
						lc, rc, err := descendIndex(
							ctx,
							incomingResponses,
							stream,
							localTree,
							nextPath,
						)
						if err != nil {
							return errors.Wrap(err, "walk")
						}

						if err = walk(
							ctx,
							logger,
							nextPath,
							lc,
							rc,
							incomingQueries,
							incomingResponses,
							stream,
							hypergraphStore,
							localTree,
							metadataOnly,
						); err != nil {
							return errors.Wrap(err, "walk")
						}
					}
				}
			}
		} else {
			logger.Info("prefix mismatch on both sides")
			sendLeafData(stream, hypergraphStore, localTree, path, metadataOnly)
		}
	}

	return nil
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
	debugTotalCoins int,
) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	query := msg.GetQuery()
	if query == nil {
		return errors.New("client did not send valid initialization message")
	}

	logger.Info("received initialization message")

	// Get the appropriate phase set
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

	branchInfo, err := getBranchInfoFromTree(idSet.GetTree(), []int32{})
	if err != nil {
		return err
	}

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	msg, err = stream.Recv()
	if err != nil {
		return err
	}
	response := msg.GetResponse()
	if response == nil {
		return errors.New(
			"client did not send valid initialization response message",
		)
	}

	incomingQueriesIn, incomingQueriesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonQuery]("server incoming")
	incomingResponsesIn, incomingResponsesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonResponse]("server incoming")
	incomingLeavesIn, incomingLeavesOut :=
		UnboundedChan[*protobufs.LeafData]("server incoming")

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				logger.Info("received disconnect")
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
				logger.Info("received error", zap.Error(err))
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if msg == nil {
				continue
			}
			switch m := msg.Payload.(type) {
			case *protobufs.HypergraphComparison_LeafData:
				incomingLeavesIn <- m.LeafData
			case *protobufs.HypergraphComparison_Query:
				incomingQueriesIn <- m.Query
			case *protobufs.HypergraphComparison_Response:
				incomingResponsesIn <- m.Response
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()
		err := walk(
			stream.Context(),
			logger,
			[]int32{},
			branchInfo,
			response,
			incomingQueriesOut,
			incomingResponsesOut,
			stream,
			localHypergraphStore,
			idSet.GetTree(),
			metadataOnly,
		)
		if err != nil {
			logger.Error("error while syncing", zap.Error(err))
		}
	}()

	lastReceived := time.Now()

outer:
	for {
		select {
		case remoteUpdate, ok := <-incomingLeavesOut:
			if !ok {
				break outer
			}

			logger.Info(
				"received leaf data",
				zap.String("key", hex.EncodeToString(remoteUpdate.Key)),
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

			lastReceived = time.Now()
		case <-time.After(5 * time.Second):
			if time.Since(lastReceived) > 5*time.Second {
				break outer
			}
		}
	}

	wg.Wait()

	total, _ := idSet.GetTree().GetMetadata()
	logger.Info(
		"current progress",
		zap.Float32("percentage", float32(total*100)/float32(debugTotalCoins)),
	)
	return nil
}

// HyperStream is the gRPC method that handles bidirectional synchronization.
func (s *hypergraphComparisonServer) HyperStream(
	stream protobufs.HypergraphComparisonService_HyperStreamServer,
) error {
	if !s.syncController.TryEstablishSyncSession() {
		return errors.New("unavailable")
	}
	defer s.syncController.EndSyncSession()

	return syncTreeBidirectionallyServer(
		stream,
		s.logger,
		s.localHypergraphStore,
		s.localHypergraph,
		false,
		s.debugTotalCoins,
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
	set *hypergraph.IdSet,
	syncController *SyncController,
	debugTotalCoins int,
	metadataOnly bool,
) error {
	logger.Info(
		"sending initialization message",
		zap.String("shard_key", hex.EncodeToString(shardKey)),
		zap.Int("phase_set", int(phaseSet)),
	)

	// Send initial query for root path
	if err := stream.Send(&protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Query{
			Query: &protobufs.HypergraphComparisonQuery{
				ShardKey:        shardKey,
				PhaseSet:        phaseSet,
				Path:            []int32{},
				Commitment:      set.GetTree().Commit(false),
				IncludeLeafData: false,
			},
		},
	}); err != nil {
		return err
	}

	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	response := msg.GetResponse()
	if response == nil {
		return errors.New(
			"server did not send valid initialization response message",
		)
	}

	branchInfo, err := getBranchInfoFromTree(set.GetTree(), []int32{})
	if err != nil {
		return err
	}

	resp := &protobufs.HypergraphComparison{
		Payload: &protobufs.HypergraphComparison_Response{
			Response: branchInfo,
		},
	}

	if err := stream.Send(resp); err != nil {
		return err
	}

	incomingQueriesIn, incomingQueriesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonQuery]("server incoming")
	incomingResponsesIn, incomingResponsesOut :=
		UnboundedChan[*protobufs.HypergraphComparisonResponse]("server incoming")
	incomingLeavesIn, incomingLeavesOut :=
		UnboundedChan[*protobufs.LeafData]("server incoming")

	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if err != nil {
				close(incomingQueriesIn)
				close(incomingResponsesIn)
				close(incomingLeavesIn)
				return
			}
			if msg == nil {
				continue
			}
			switch m := msg.Payload.(type) {
			case *protobufs.HypergraphComparison_LeafData:
				incomingLeavesIn <- m.LeafData
			case *protobufs.HypergraphComparison_Query:
				incomingQueriesIn <- m.Query
			case *protobufs.HypergraphComparison_Response:
				incomingResponsesIn <- m.Response
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := walk(
			stream.Context(),
			logger,
			[]int32{},
			branchInfo,
			response,
			incomingQueriesOut,
			incomingResponsesOut,
			stream,
			hypergraphStore,
			set.GetTree(),
			metadataOnly,
		)
		if err != nil {
			logger.Error("error while syncing", zap.Error(err))
		}
	}()

	lastReceived := time.Now()

outer:
	for {
		select {
		case remoteUpdate, ok := <-incomingLeavesOut:
			if !ok {
				break outer
			}

			logger.Info(
				"received leaf data",
				zap.String("key", hex.EncodeToString(remoteUpdate.Key)),
			)

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

			set.Add(hypergraph.AtomFromBytes(remoteUpdate.Value))

			lastReceived = time.Now()
		case <-time.After(5 * time.Second):
			if time.Since(lastReceived) > 5*time.Second {
				break outer
			}
		}
	}

	wg.Wait()

	total, _ := set.GetTree().GetMetadata()
	logger.Info(
		"current progress",
		zap.Float32("percentage", float32(total*100)/float32(debugTotalCoins)),
	)
	return nil
}

func UnboundedChan[T any](purpose string) (chan<- T, <-chan T) {
	in := make(chan T)
	out := make(chan T)
	go func() {
		var queue []T
		for {
			var active chan T
			var next T
			if len(queue) > 0 {
				active = out
				next = queue[0]
			}
			select {
			case msg, ok := <-in:
				if !ok {
					return
				}

				queue = append(queue, msg)
			case active <- next:
				queue = queue[1:]
			}
		}
	}()
	return in, out
}
