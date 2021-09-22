package miner

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bitclout/backend/routes"
	"github.com/bitclout/core/lib"
	"io/ioutil"
	"net/http"
	"runtime"
	"time"

	"github.com/sasha-s/go-deadlock"

	"github.com/golang/glog"
)

type RemoteMiner struct {
	// IP:PORT or DOMAIN:PORT of the remote node used to get block templates and to
	// submit blocks.
	RemoteNode string

	// The public key of the miner
	PublicKeyBase58Check string

	NumThreads         int64
	IterationsPerCycle int64
	// How many seconds we wait before asking the BlockProducer for a fresh set of
	// templates.
	TemplateRefreshIntervalSeconds float64

	mtxLatestBLockTemplates deadlock.RWMutex
	latestBlockHeaders      []*lib.MsgBitCloutHeader
	latestExtraDatas        []uint64
	latestBlockID           string
	currentDiffTarget       *lib.BlockHash
}

func NewRemoteMiner(
	remoteNode string, publicKeyBase58Check string, _numThreads int64, iterationsPerCycle int64,
	templateRefreshIntervalSeconds float64) *RemoteMiner {

	// Compute the number of threads we have
	numMiningThreads := int64(runtime.NumCPU())
	if _numThreads > 0 {
		numMiningThreads = _numThreads
	}

	bb := &RemoteMiner{
		RemoteNode:                     remoteNode,
		PublicKeyBase58Check:           publicKeyBase58Check,
		NumThreads:                     numMiningThreads,
		IterationsPerCycle:             iterationsPerCycle,
		TemplateRefreshIntervalSeconds: templateRefreshIntervalSeconds,
	}

	// Initialize the first block templates
	if err := bb.RefreshBlockTemplates(); err != nil {
		panic(err)
	}
	if bb.latestBlockID == "" {
		panic("Initial call to RefreshBlockTemplates failed. Is your " +
			"--remote_block_producer set up to produce blocks?")
	}

	return bb
}

func (bb *RemoteMiner) GetBlockTemplate(threadIndex int64) (
	_hdr *lib.MsgBitCloutHeader, _extraNonce uint64, _blockID string, _diffTarget *lib.BlockHash) {

	bb.mtxLatestBLockTemplates.RLock()
	defer bb.mtxLatestBLockTemplates.RUnlock()

	return bb.latestBlockHeaders[threadIndex], bb.latestExtraDatas[threadIndex], bb.latestBlockID, bb.currentDiffTarget
}

func (bb *RemoteMiner) SubmitWinningHeader(
	header *lib.MsgBitCloutHeader, extraData uint64, blockID string) error {
	headerBytes, err := header.ToBytes(false)
	if err != nil {
		return fmt.Errorf("Error converting header to bytes: %v", err)
	}

	// Send the winning header to the BlockProducer
	submitBlockRequest := &routes.SubmitBlockRequest{
		PublicKeyBase58Check: bb.PublicKeyBase58Check,
		Header:               headerBytes,
		ExtraData:            extraData,
		BlockID:              blockID,
	}
	jsonRequest, err := json.Marshal(submitBlockRequest)
	if err != nil {
		return fmt.Errorf("Error marshaling SubmitBlock request: %v", err)
	}
	resObj, err := http.Post(
		fmt.Sprintf("%s%s", bb.RemoteNode, routes.RoutePathSubmitBlock),
		"application/json", /*contentType*/
		bytes.NewBuffer(jsonRequest))
	if err != nil {
		return fmt.Errorf("Error submitting block: %v", err)
	}

	res := &routes.SubmitBlockResponse{}
	if err := json.NewDecoder(resObj.Body).Decode(&res); err != nil {
		return fmt.Errorf("Error decoding response: %v", err)
	}
	resObj.Body.Close()

	// Log
	if !res.IsMainChain {
		glog.Debugf("Submitted block, but it's not on the main chain: isMainChain: %v, isOrphan: %v", res.IsMainChain, res.IsOrphan)
	} else {
		hash, _ := header.Hash()
		glog.Infof("========== Successfully mined a block on the main chain! Height: %v, Hash: %v ==========", header.Height, hash)
	}

	// Refresh the block templates.
	if err := bb.RefreshBlockTemplates(); err != nil {
		glog.Errorf("Error refreshing block templates: %v", err)
	}
	glog.Debugf("Successfully refreshed block templates after SubmitWinningHeader")

	return nil
}

func (bb *RemoteMiner) RefreshBlockTemplates() error {
	// Get a bunch of block templates from the server
	getBlockTemplateRequest := &routes.GetBlockTemplateRequest{
		PublicKeyBase58Check: bb.PublicKeyBase58Check,
		NumHeaders:           bb.NumThreads,
		HeaderVersion: 		  lib.CurrentHeaderVersion,
	}
	jsonRequest, err := json.Marshal(getBlockTemplateRequest)
	if err != nil {
		return fmt.Errorf("Error marshaling block template request: %v", err)
	}
	resObj, err := http.Post(
		fmt.Sprintf("%s%s", bb.RemoteNode, routes.RoutePathGetBlockTemplate),
		"application/json", /*contentType*/
		bytes.NewBuffer(jsonRequest))
	if err != nil {
		return fmt.Errorf("Error fetching block templates: %v", err)
	}
	if resObj.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resObj.Body)
		return fmt.Errorf("Error fetching block templates; status code %v: %v", resObj.StatusCode, string(body))
	}

	res := &routes.GetBlockTemplateResponse{}
	if err := json.NewDecoder(resObj.Body).Decode(&res); err != nil {
		return fmt.Errorf("Error decoding response: %v", err)
	}
	resObj.Body.Close()

	// Update the latest blocks we're mining on
	bb.mtxLatestBLockTemplates.Lock()
	defer bb.mtxLatestBLockTemplates.Unlock()

	bb.latestBlockHeaders = []*lib.MsgBitCloutHeader{}
	for _, hdrBytes := range res.Headers {
		header := &lib.MsgBitCloutHeader{}
		if err := header.FromBytes(hdrBytes); err != nil {
			return fmt.Errorf("Error parsing headers in response: %v", err)
		}
		bb.latestBlockHeaders = append(bb.latestBlockHeaders, header)
	}

	diffTargetBytes, err := hex.DecodeString(res.DifficultyTargetHex)
	if err != nil {
		return fmt.Errorf("Error parsing difficulty target: %v", err)
	}
	diffTargetHash := &lib.BlockHash{}
	copy(diffTargetHash[:], diffTargetBytes)

	bb.latestExtraDatas = res.ExtraDatas
	bb.latestBlockID = res.BlockID
	bb.currentDiffTarget = diffTargetHash

	return nil
}

type SingleThread struct {
	ThreadIndex        int64
	RemoteMiner        *RemoteMiner
	IterationsPerCycle int64
}

func NewSingleThread(threadIndex int64, RemoteMiner *RemoteMiner,
	iterationsPerCycle int64) *SingleThread {

	return &SingleThread{
		ThreadIndex:        threadIndex,
		RemoteMiner:        RemoteMiner,
		IterationsPerCycle: iterationsPerCycle,
	}
}

func (ss *SingleThread) Loop() {
	// Keep track of the most recent nonce and just keep incrementing it
	// It should loop back around if we overflow.
	startNonce := uint64(0)
	for {
		// Get a header from the template manager
		hdr, extraData, blockID, diffTarget := ss.RemoteMiner.GetBlockTemplate(ss.ThreadIndex)

		// Set the startNonce and increment it by the number of iterations we're doing
		// in this cycle for next time.
		hdr.Nonce = startNonce
		startNonce += uint64(ss.IterationsPerCycle)

		// Hash on it
		timeBefore := time.Now()
		bestHash, bestNonce, err := lib.FindLowestHash(hdr, uint64(ss.IterationsPerCycle))
		glog.Tracef("Time per iteration: %v", time.Since(timeBefore))
		if err != nil {
			// If there's an error log it and break out.
			glog.Errorf("Error while mining: %v", err)
			break
		}

		if lib.LessThan(diffTarget, bestHash) {
			continue
		}

		// If we get here then it means our bestHash has beaten the target and
		// that bestNonce is the nonce that generates the solution hash.

		// Set the nonce on the header
		hdr.Nonce = bestNonce

		// Submit the winning block to the block manager. If this works then the manager
		// will refresh the headers before the next iteration.
		err = ss.RemoteMiner.SubmitWinningHeader(hdr, extraData, blockID)
		if err != nil {
			glog.Errorf("Error submitting winning header: %v", err)
		}
	}
}

func (bb *RemoteMiner) Start() {
	// Create and start a SingleThread object for each thread and loop it.
	for ii := int64(0); ii < bb.NumThreads; ii++ {
		ss := NewSingleThread(ii, bb, bb.IterationsPerCycle)
		go func() {
			ss.Loop()
		}()
	}

	glog.Infof("Threads started: %v", bb.NumThreads)

	// Now query the BlockProducer at regular intervals for fresh headers.
	for {
		if err := bb.RefreshBlockTemplates(); err != nil {
			glog.Errorf("Error refreshing block templates: %v", err)
		}
		glog.Debugf("Successfully refreshed block templates")
		time.Sleep(time.Duration(bb.TemplateRefreshIntervalSeconds) * time.Second)
	}
}
