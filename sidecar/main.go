//go:build !js && !wasm

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	gotime "time"

	"github.com/cloudflare/circl/sign/ed448"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
	"source.quilibrium.com/quilibrium/monorepo/sidecar/internal"
)

var (
	peerAddress = flag.String(
		"peer-address",
		"/ip4/0.0.0.0/tcp/8339",
		"listening address of the peer, uses multiaddr format (e.g. /ip4/127.0.0.1/tcp/8339)",
	)
)

var logger *zap.Logger
var wg sync.WaitGroup
var ctx context.Context
var cancel context.CancelFunc
var frameMessageProcessorCh = make(chan *pb.Message, 65536)
var pubSub *p2p.BlossomSub
var dataTimeReel *time.DataTimeReel
var recentlyProcessedFrames *lru.Cache[string, struct{}]
var frameProver qcrypto.FrameProver
var inclusionProver qcrypto.InclusionProver
var keyManager keys.KeyManager
var lastProven uint64
var proverTrie *tries.RollingFrecencyCritbitTrie

func main() {
	flag.Parse()
	ctx, cancel = context.WithCancel(context.Background())
	fmt.Println("initializing")

	kzg.Init()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	recentlyProcessedFrames, _ = lru.New[string, struct{}](25)
	logger, _ = zap.NewDevelopment()
	var privKey crypto.PrivKey
	keyManager,
		_,
		_,
		privKey = generateTestProver()
	privKeyBytes, _ := privKey.Raw()
	filter := "0000000000000000000000010000000000000000000010000000000000000001"
	frameFilter, _ := hex.DecodeString(filter)
	engConfig := &config.EngineConfig{
		Filter:      filter,
		GenesisSeed: strings.Repeat("00", 516),
		Difficulty:  200000,
	}
	config := config.P2PConfig{
		BootstrapPeers: []string{
			"/ip4/91.242.214.79/udp/8336/quic-v1/p2p/QmNSGavG2DfJwGpHmzKjVmTD6CVSyJsUFTXsW4JXt2eySR",
		},
		ListenMultiaddr: *peerAddress,
		PeerPrivKey:     hex.EncodeToString(privKeyBytes),
		Network:         1,
	}
	config = config.WithDefaults()
	pubSub = p2p.NewBlossomSub(&config, logger)
	frameProver = qcrypto.NewCachedWesolowskiFrameProver(logger)
	inclusionProver = qcrypto.NewKZGInclusionProver(logger)
	db := store.NewInMemKVDB()
	clockStore := store.NewPebbleClockStore(db, logger)
	prover := qcrypto.NewWesolowskiFrameProver(logger)

	dataTimeReel = time.NewDataTimeReel(
		frameFilter,
		logger,
		clockStore,
		engConfig,
		prover,
		func(
			txn store.Transaction,
			frame *protobufs.ClockFrame,
			triesAtFrame []*tries.RollingFrecencyCritbitTrie,
		) (
			[]*tries.RollingFrecencyCritbitTrie,
			error,
		) {
			return triesAtFrame, nil
		},
		bytes.Repeat([]byte{0x00}, 516),
		&qcrypto.InclusionAggregateProof{
			InclusionCommitments: []*qcrypto.InclusionCommitment{},
			AggregateCommitment:  []byte{},
			Proof:                []byte{},
		},
		[][]byte{},
		true,
	)
	go runFrameMessageHandler()

	pubSub.RegisterValidator(frameFilter, validateFrameMessage, true)
	pubSub.Subscribe(frameFilter, handleFrameMessage)

	Start(ctx, keyManager)
	defer Stop()

	<-done
}

func runFrameMessageHandler() {
	wg.Add(1)
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-frameMessageProcessorCh:
			logger.Debug("handling frame message")
			msg := &protobufs.Message{}

			if err := proto.Unmarshal(message.Data, msg); err != nil {
				logger.Debug("cannot unmarshal data", zap.Error(err))
				continue
			}

			a := &anypb.Any{}
			if err := proto.Unmarshal(msg.Payload, a); err != nil {
				logger.Debug("cannot unmarshal payload", zap.Error(err))
				continue
			}

			switch a.TypeUrl {
			case protobufs.ClockFrameType:
				if err := handleClockFrameData(
					message.From,
					msg.Address,
					a,
				); err != nil {
					logger.Debug("could not handle clock frame data", zap.Error(err))
				}
			}
		}
	}
}

func handleClockFrameData(
	peerID []byte,
	address []byte,
	a *anypb.Any,
) error {
	if bytes.Equal(peerID, pubSub.GetPeerID()) {
		return nil
	}

	frame := &protobufs.ClockFrame{}
	if err := a.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	return handleClockFrame(peerID, address, frame)
}

func handleFrameMessage(
	message *pb.Message,
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case frameMessageProcessorCh <- message:
	default:
		logger.Warn("dropping frame message")
	}
	return nil
}

func handleClockFrame(
	peerID []byte,
	address []byte,
	frame *protobufs.ClockFrame,
) error {
	if frame == nil {
		return errors.Wrap(errors.New("frame is nil"), "handle clock frame")
	}

	if _, ok := recentlyProcessedFrames.Peek(string(frame.Output)); ok {
		return nil
	}

	recentlyProcessedFrames.Add(string(frame.Output), struct{}{})

	logger.Debug(
		"got clock frame",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	if err := frameProver.VerifyDataClockFrame(frame); err != nil {
		logger.Debug("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	logger.Debug(
		"clock frame was valid",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	head, err := dataTimeReel.Head()
	if err != nil {
		panic(err)
	}

	if frame.FrameNumber > head.FrameNumber {
		if _, err := dataTimeReel.Insert(ctx, frame); err != nil {
			logger.Debug("could not insert frame", zap.Error(err))
		}
	}

	return nil
}

func validateFrameMessage(peerID peer.ID, message *pb.Message) p2p.ValidationResult {
	msg := &protobufs.Message{}
	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return p2p.ValidationResultReject
	}
	a := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, a); err != nil {
		return p2p.ValidationResultReject
	}
	switch a.TypeUrl {
	case protobufs.ClockFrameType:
		frame := &protobufs.ClockFrame{}
		if err := proto.Unmarshal(a.Value, frame); err != nil {
			return p2p.ValidationResultReject
		}
		if ts := gotime.UnixMilli(frame.Timestamp); gotime.Since(ts) > 20*gotime.Second {
			return p2p.ValidationResultIgnore
		}
		return p2p.ValidationResultAccept
	default:
		return p2p.ValidationResultReject
	}
}

func generateTestProver() (
	keys.KeyManager,
	peer.ID,
	[]byte,
	crypto.PrivKey,
) {
	keyManager := keys.NewInMemoryKeyManager()
	keyManager.CreateSigningKey(
		"test-key",
		keys.KeyTypeEd448,
	)
	k, err := keyManager.GetRawKey("test-key")
	if err != nil {
		panic(err)
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey([]byte(k.PrivateKey))
	if err != nil {
		panic(err)
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(err)
	}

	keyManager.CreateSigningKey(
		"proving-key",
		keys.KeyTypeEd448,
	)
	pk, err := keyManager.GetRawKey("proving-key")
	if err != nil {
		panic(err)
	}

	pprivKey, err := crypto.UnmarshalEd448PrivateKey([]byte(pk.PrivateKey))
	if err != nil {
		panic(err)
	}

	ppub := pprivKey.GetPublic()
	ppubKey, err := ppub.Raw()
	if err != nil {
		panic(err)
	}

	return keyManager,
		id,
		ppubKey,
		privKey
}

func prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if lastProven >= previousFrame.FrameNumber && lastProven != 0 {
		return previousFrame, nil
	}
	executionOutput := &protobufs.IntrinsicExecutionOutput{}

	logger.Info(
		"proving new frame",
	)

	a := sha3.Sum256([]byte("sidecar"))
	executionOutput.Address = a[:]
	var err error
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	data, err := proto.Marshal(executionOutput)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	logger.Debug("encoded execution output")
	digest := sha3.NewShake256()
	_, err = digest.Write(data)
	if err != nil {
		logger.Error(
			"error writing digest",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "prove")
	}

	expand := make([]byte, 1024)
	_, err = digest.Read(expand)
	if err != nil {
		logger.Error(
			"error expanding digest",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "prove")
	}

	commitment, err := inclusionProver.CommitRaw(
		expand,
		16,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	logger.Debug("creating kzg proof")
	proof, err := inclusionProver.ProveRaw(
		expand,
		int(expand[0]%16),
		16,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	logger.Debug("finalizing execution proof")

	filter := "0000000000000000000000010000000000000000000010000000000000000001"

	filterBytes, _ := hex.DecodeString(filter)
	keyManager.CreateSigningKey(
		"proving-key",
		keys.KeyTypeEd448,
	)
	pk, err := keyManager.GetRawKey("proving-key")
	if err != nil {
		panic(err)
	}

	provingKey, err := crypto.UnmarshalEd448PrivateKey([]byte(pk.PrivateKey))
	if err != nil {
		panic(err)
	}
	privateKey, err := provingKey.Raw()
	if err != nil {
		panic(err)
	}
	prover := ed448.PrivateKey(privateKey)
	frame, err := frameProver.ProveDataClockFrame(
		previousFrame,
		[][]byte{proof},
		[]*protobufs.InclusionAggregateProof{
			{
				Filter:      filterBytes,
				FrameNumber: previousFrame.FrameNumber + 1,
				InclusionCommitments: []*protobufs.InclusionCommitment{
					{
						Filter:      filterBytes,
						FrameNumber: previousFrame.FrameNumber + 1,
						TypeUrl:     protobufs.IntrinsicExecutionOutputType,
						Commitment:  commitment,
						Data:        data,
						Position:    0,
					},
				},
				Proof: proof,
			},
		},
		prover,
		gotime.Now().UnixMilli(),
		200000,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	lastProven = previousFrame.FrameNumber
	logger.Info(
		"returning new proven frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
		zap.Int("commitment_count", len(frame.Input[516:])/74),
	)
	return frame, nil
}

func Start(ctx context.Context, keyManager keys.KeyManager) {
	go dataTimeReel.Start()
	go runLoop()
}

func runLoop() {
	wg.Add(1)
	defer wg.Done()
	dataFrameCh := dataTimeReel.NewFrameCh()
	runOnce := true
	for {
		peerCount := pubSub.GetNetworkPeersCount()
		if peerCount < 3 {
			logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			select {
			case <-ctx.Done():
				return
			case <-gotime.After(1 * gotime.Second):
			}
		} else {
			latestFrame, err := dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			if latestFrame == nil {
				gotime.Sleep(10 * gotime.Second)
				continue
			}

			if runOnce {
				dataFrame, err := dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				latestFrame = processFrame(latestFrame, dataFrame)
				runOnce = false
			}

			select {
			case <-ctx.Done():
				return
			case dataFrame := <-dataFrameCh:
				if err := publishProof(dataFrame); err != nil {
					logger.Error("could not publish proof", zap.Error(err))
				}
				latestFrame = processFrame(latestFrame, dataFrame)
			}
		}
	}
}

func publishMessage(
	filter []byte,
	message proto.Message,
) error {
	a := &anypb.Any{}
	if err := a.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	a.TypeUrl = strings.Replace(
		a.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(a)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	addr := sha3.Sum256([]byte("sidecar"))
	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: addr[:],
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return pubSub.PublishToBitmask(filter, data)
}

func publishProof(
	frame *protobufs.ClockFrame,
) error {
	logger.Debug(
		"publishing frame and aggregations",
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	filter := "0000000000000000000000010000000000000000000010000000000000000001"
	frameFilter, _ := hex.DecodeString(filter)
	if err := publishMessage(frameFilter, frame); err != nil {
		logger.Error("error publishing clock frame", zap.Error(err))
	}

	return nil
}

func processFrame(
	latestFrame *protobufs.ClockFrame,
	dataFrame *protobufs.ClockFrame,
) *protobufs.ClockFrame {
	logger.Info(
		"current frame head",
		zap.Uint64("frame_number", dataFrame.FrameNumber),
		zap.Duration("frame_age", internal.Since(dataFrame)),
	)
	var err error

	if latestFrame != nil && dataFrame.FrameNumber > latestFrame.FrameNumber {
		latestFrame = dataFrame
	}

	var nextFrame *protobufs.ClockFrame
	if nextFrame, err = prove(dataFrame); err != nil {
		logger.Error("could not prove", zap.Error(err))
		return dataFrame
	}

	if _, err := dataTimeReel.Insert(ctx, nextFrame); err != nil {
		logger.Debug("could not insert frame", zap.Error(err))
	}

	return nextFrame
}

func Stop() {
	filter := "0000000000000000000000010000000000000000000010000000000000000001"
	frameFilter, _ := hex.DecodeString(filter)
	pubSub.Unsubscribe(frameFilter, false)
	pubSub.UnregisterValidator(frameFilter)
	dataTimeReel.Stop()
	cancel()
	wg.Wait()
}
