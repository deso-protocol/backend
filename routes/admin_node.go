package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bitclout/core/lib"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/golang/glog"
)

// NodeControlRequest ...
type NodeControlRequest struct {
	// An address in <IP>:<Port> format.
	Address string `safeForLogging:"true"`

	// A comma-separated list of miner public keys to use.
	MinerPublicKeys string `safeForLogging:"true"`

	// The type of operation to perform on the node.
	OperationType string `safeForLogging:"true"`

	JWT            string
	AdminPublicKey string
}

type NodeStatusResponse struct {
	// A summary of what the node is currently doing.
	State string `safeForLogging:"true"`

	// We generally track the latest header we have and the latest block we have
	// separately since headers-first synchronization can cause the latest header
	// to diverge slightly from the latest block.
	LatestHeaderHeight     uint32 `safeForLogging:"true"`
	LatestHeaderHash       string `safeForLogging:"true"`
	LatestHeaderTstampSecs uint32 `safeForLogging:"true"`

	LatestBlockHeight     uint32 `safeForLogging:"true"`
	LatestBlockHash       string `safeForLogging:"true"`
	LatestBlockTstampSecs uint32 `safeForLogging:"true"`
	LatestTxIndexHeight   uint32 `safeForLogging:"true"`

	// This is non-zero unless the main header chain is fully current. It can be
	// an estimate in cases where we don't know exactly what the tstamp of the
	// current main chain is.
	HeadersRemaining uint32 `safeForLogging:"true"`
	// This is non-zero unless the main header chain is fully current and all
	// the corresponding blocks have been downloaded.
	BlocksRemaining uint32 `safeForLogging:"true"`
}

type PeerResponse struct {
	IP           string
	ProtocolPort uint16
	IsSyncPeer   bool
}

type BitcoinExchangeResponseInfo struct {
	BitcoinTxnHash string
	BitcoinTxnHex  string
	IsMined        bool
}

// NodeControlResponse ...
type NodeControlResponse struct {
	// The current status the BitClout node is at in terms of syncing the BitClout
	// chain.
	BitCloutStatus *NodeStatusResponse
	BitcoinStatus  *NodeStatusResponse

	BitCloutOutboundPeers    []*PeerResponse
	BitCloutInboundPeers     []*PeerResponse
	BitCloutUnconnectedPeers []*PeerResponse

	BitcoinSyncPeer         *PeerResponse
	BitcoinUnconnectedPeers []*PeerResponse
	BitcoinExchangeTxns     []*BitcoinExchangeResponseInfo `safeForLogging:"true"`

	MinerPublicKeys []string
}

func parseIPAndPort(address string) (string, uint16) {
	ipAndPort := strings.Split(address, ":")
	ip := address
	port := uint16(0)
	if len(ipAndPort) >= 2 {
		portStr := ipAndPort[len(ipAndPort)-1]
		parsedPort, err := strconv.Atoi(portStr)
		if err == nil && parsedPort <= math.MaxUint16 {
			// Only set the port if we didn't have an error during conversion.
			port = uint16(parsedPort)
			ip = strings.Join(ipAndPort[:len(ipAndPort)-1], ":")
		}
	}

	return ip, port
}

func (fes *APIServer) _handleNodeControlGetInfo(
	requestData *NodeControlRequest, ww http.ResponseWriter) {

	// Set some fields we'll need to use down below.
	bitcloutChainState := fes.blockchain.ChainState()
	bitcloutHeaderTip := fes.blockchain.HeaderTip()
	bitcloutBlockTip := fes.blockchain.BlockTip()
	isBitcoinChainCurrent := fes.backendServer.GetBitcoinManager().IsCurrent(false)
	bitcoinHeaderTip := fes.backendServer.GetBitcoinManager().HeaderTip()

	// Compute the fields for the BitClout NodeStatusResponse
	bitcloutNodeStatus := &NodeStatusResponse{}
	if !isBitcoinChainCurrent {
		bitcloutNodeStatus.State = "SYNCING_BITCOIN"
	} else {
		bitcloutNodeStatus.State = bitcloutChainState.String()
	}
	// Main header chain fields
	{
		bitcloutNodeStatus.LatestHeaderHeight = bitcloutHeaderTip.Height
		bitcloutNodeStatus.LatestHeaderHash = hex.EncodeToString(bitcloutHeaderTip.Hash[:])
		bitcloutNodeStatus.LatestHeaderTstampSecs = uint32(bitcloutHeaderTip.Header.TstampSecs)
	}
	// Main block chain fields
	{
		bitcloutNodeStatus.LatestBlockHeight = bitcloutBlockTip.Height
		bitcloutNodeStatus.LatestBlockHash = hex.EncodeToString(bitcloutBlockTip.Hash[:])
		bitcloutNodeStatus.LatestBlockTstampSecs = uint32(bitcloutBlockTip.Header.TstampSecs)
	}
	if fes.TxIndexChain != nil {
		// TxIndex status
		bitcloutNodeStatus.LatestTxIndexHeight = fes.TxIndexChain.BlockTip().Height
	}
	// We only have headers remaining if we're in this state.
	if bitcloutChainState == lib.SyncStateSyncingHeaders {
		bitcloutNodeStatus.HeadersRemaining = uint32(
			(time.Now().Unix() - int64(bitcloutNodeStatus.LatestHeaderTstampSecs)) /
				int64(fes.Params.TimeBetweenBlocks.Seconds()))
	}
	// We only have blocks remaining if we're in one of the following states.
	if bitcloutChainState == lib.SyncStateSyncingHeaders ||
		bitcloutChainState == lib.SyncStateSyncingBlocks ||
		bitcloutChainState == lib.SyncStateNeedBlocksss {

		bitcloutNodeStatus.BlocksRemaining = bitcloutHeaderTip.Height - bitcloutBlockTip.Height
	}

	// Get and sort the peers so we have a consistent ordering.
	allBitCloutPeers := fes.backendServer.GetConnectionManager().GetAllPeers()
	sort.Slice(allBitCloutPeers, func(ii, jj int) bool {
		// Use a hash to get a random but deterministic ordering.
		return allBitCloutPeers[ii].Address() < allBitCloutPeers[jj].Address()
	})

	// Rack up the inbound and outbound peers from the connection manager.
	bitcloutOutboundPeers := []*PeerResponse{}
	bitcloutInboundPeers := []*PeerResponse{}
	bitcloutUnconnectedPeers := []*PeerResponse{}
	existingBitCloutPeers := make(map[string]bool)
	syncPeer := fes.backendServer.SyncPeer
	for _, bitcloutPeer := range allBitCloutPeers {
		isSyncPeer := false
		if syncPeer != nil && (bitcloutPeer.String() == syncPeer.String()) {
			isSyncPeer = true
		}
		currentPeerRes := &PeerResponse{
			IP:           bitcloutPeer.IP(),
			ProtocolPort: bitcloutPeer.Port(),
			IsSyncPeer:   isSyncPeer,
		}
		if bitcloutPeer.IsOutbound() {
			bitcloutOutboundPeers = append(bitcloutOutboundPeers, currentPeerRes)
		} else {
			bitcloutInboundPeers = append(bitcloutInboundPeers, currentPeerRes)
		}

		existingBitCloutPeers[currentPeerRes.IP+fmt.Sprintf(":%d", currentPeerRes.ProtocolPort)] = true
	}
	// Return some bitclout addrs from the addr manager.
	bitcloutAddrs := fes.backendServer.GetConnectionManager().GetAddrManager().AddressCache()
	sort.Slice(bitcloutAddrs, func(ii, jj int) bool {
		// Use a hash to get a random but deterministic ordering.
		hashI := string(lib.Sha256DoubleHash([]byte(bitcloutAddrs[ii].IP.String() + fmt.Sprintf(":%d", bitcloutAddrs[ii].Port)))[:])
		hashJ := string(lib.Sha256DoubleHash([]byte(bitcloutAddrs[jj].IP.String() + fmt.Sprintf(":%d", bitcloutAddrs[jj].Port)))[:])

		return hashI < hashJ
	})
	for _, netAddr := range bitcloutAddrs {
		if len(bitcloutUnconnectedPeers) >= 250 {
			break
		}
		addr := netAddr.IP.String() + fmt.Sprintf(":%d", netAddr.Port)
		if _, exists := existingBitCloutPeers[addr]; exists {
			continue
		}
		bitcloutUnconnectedPeers = append(bitcloutUnconnectedPeers, &PeerResponse{
			IP:           netAddr.IP.String(),
			ProtocolPort: netAddr.Port,
			// Unconnected peers are not sync peers so leave it set to false.
		})
	}

	// Compute the fields for the Bitcoin NodeStatusResponse
	bitcoinNodeStatus := &NodeStatusResponse{}
	if fes.backendServer.GetBitcoinManager().IsCurrent(true) {
		bitcoinNodeStatus.State = "FULLY_CURRENT"
	} else if fes.backendServer.GetBitcoinManager().IsCurrent(false) {
		bitcoinNodeStatus.State = "TENTATIVELY_CURRENT"
	} else {
		bitcoinNodeStatus.State = "SYNCING"
	}
	// For the Bitcoin part of this we only set information on headers.
	{
		bitcoinNodeStatus.LatestHeaderHeight = bitcoinHeaderTip.Height
		bitcoinNodeStatus.LatestHeaderHash = (chainhash.Hash)(*bitcoinHeaderTip.Hash).String()
		bitcoinNodeStatus.LatestHeaderTstampSecs = uint32(bitcoinHeaderTip.Header.TstampSecs)
	}
	if !isBitcoinChainCurrent {
		bitcoinNodeStatus.HeadersRemaining = uint32(
			(time.Now().Unix() - int64(bitcoinNodeStatus.LatestHeaderTstampSecs)) /
				int64(fes.Params.BitcoinTimeBetweenBlocks.Seconds()))
	}
	// Set the current Bitcoin sync peer.
	var bitcoinSyncPeer *PeerResponse
	bitcoinSyncConn := fes.backendServer.GetBitcoinManager().SyncConn()
	if bitcoinSyncConn != nil {
		// This is annoying but for the sync peer we need to split the IP from the port
		// because all we have is RemoteAddr which is a string. RemoteAddr is always
		// <IP>:<port> and so the last element after the colon when we Split() the
		// RemoteAddr is the port.
		ip, port := parseIPAndPort(bitcoinSyncConn.RemoteAddr().String())

		bitcoinSyncPeer = &PeerResponse{
			IP:           ip,
			ProtocolPort: port,
			IsSyncPeer: true,
		}
	}
	// Get some alternative peers from the Bitcoin addrmgr
	bitcoinUnconnectedPeers := []*PeerResponse{}
	bitcoinAddrs := fes.backendServer.GetBitcoinManager().GetAddrManager().AddressCache()
	sort.Slice(bitcoinAddrs, func(ii, jj int) bool {
		// Use a hash to get a deterministic but random order.
		hashI := string(lib.Sha256DoubleHash([]byte(bitcoinAddrs[ii].IP.String() + fmt.Sprintf(":%d", bitcoinAddrs[ii].Port)))[:])
		hashJ := string(lib.Sha256DoubleHash([]byte(bitcoinAddrs[jj].IP.String() + fmt.Sprintf(":%d", bitcoinAddrs[jj].Port)))[:])
		return hashI < hashJ
	})
	for _, netAddr := range bitcoinAddrs {
		// Only IPV4 addresses are currently supported for Bitcoin.
		if netAddr.IP.To4() == nil {
			continue
		}
		if len(bitcoinUnconnectedPeers) >= 250 {
			break
		}
		if bitcoinSyncPeer != nil && bitcoinSyncPeer.IP == netAddr.IP.String() {
			continue
		}
		bitcoinUnconnectedPeers = append(bitcoinUnconnectedPeers, &PeerResponse{
			IP:           netAddr.IP.String(),
			ProtocolPort: netAddr.Port,
			// This is not a sync peer by definition.
		})
	}

	// Encode the miner public keys as strings.
	minerPublicKeyStrs := []string{}
	for _, publicKey := range fes.backendServer.GetMiner().PublicKeys {
		minerPublicKeyStrs = append(minerPublicKeyStrs, lib.PkToString(
			publicKey.SerializeCompressed(), fes.Params))
	}

	// Iterate through the BitcoinExchange txns in the mempool and add them to the
	// response as well.
	// TODO: This could be made more general.
	bitcoinExchangeTxns := []*BitcoinExchangeResponseInfo{}
	txns, _, _ := fes.mempool.GetTransactionsOrderedByTimeAdded()
	for _, txD := range txns {
		txn := txD.Tx
		if txn.TxnMeta.GetTxnType() == lib.TxnTypeBitcoinExchange {
			txnMeta := txn.TxnMeta.(*lib.BitcoinExchangeMetadata)

			bitcoinTxnBytes := bytes.Buffer{}
			err := txnMeta.BitcoinTransaction.SerializeNoWitness(&bitcoinTxnBytes)
			if err != nil {
				glog.Error(err)
			}
			bitcoinExchangeTxns = append(bitcoinExchangeTxns, &BitcoinExchangeResponseInfo{
				BitcoinTxnHash: txnMeta.BitcoinTransaction.TxHash().String(),
				BitcoinTxnHex:  hex.EncodeToString(bitcoinTxnBytes.Bytes()),
				IsMined:        !lib.IsUnminedBitcoinExchange(txnMeta),
			})
		}
	}

	res := NodeControlResponse{
		BitCloutStatus: bitcloutNodeStatus,
		BitcoinStatus:  bitcoinNodeStatus,

		BitCloutOutboundPeers:    bitcloutOutboundPeers,
		BitCloutInboundPeers:     bitcloutInboundPeers,
		BitCloutUnconnectedPeers: bitcloutUnconnectedPeers,

		BitcoinSyncPeer:         bitcoinSyncPeer,
		BitcoinUnconnectedPeers: bitcoinUnconnectedPeers,
		BitcoinExchangeTxns:     bitcoinExchangeTxns,

		MinerPublicKeys: minerPublicKeyStrs,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) _handleConnectBitCloutNode(
	ww http.ResponseWriter, ip string, protocolPort uint16) {

	// Don't connect to the peer if we're already aware of them.
	for _, bitcloutPeer := range fes.backendServer.GetConnectionManager().GetAllPeers() {
		if strings.Contains(bitcloutPeer.Address(), ip+fmt.Sprintf(":%d", protocolPort)) {
			_AddBadRequestError(ww, fmt.Sprintf("You are already connected to peer %s:%d", ip, protocolPort))
			return
		}
	}

	// Give the peer a dial just to make sure it's alive as a sanity-check.
	conn, err := net.DialTimeout("tcp", ip+fmt.Sprintf(":%d", protocolPort), fes.Params.DialTimeout)
	if err != nil {
		// Give a clean error we can display in this case.
		_AddBadRequestError(ww, fmt.Sprintf("Cannot connect to node %s:%d: %v", ip, protocolPort, err))
		return
	}
	conn.Close()

	// connectPeer has an infinite loop in it so we want to avoid letting it run
	// forever.
	// TODO: Right now every time this gets messed up we kick off a spinning
	// goroutine. It's not so bad because connectPeer has an exponentially
	// increasing retry delay, but we should still clean it up at some point.
	connectPeerDone := make(chan bool)
	go func() {
		netAddr, err := fes.backendServer.GetConnectionManager().GetAddrManager().HostToNetAddress(ip, protocolPort, 0)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("_handleConnectBitCloutNode: Cannot connect to node %s:%d: %v", ip, protocolPort, err))
			return
		}
		fes.backendServer.GetConnectionManager().ConnectPeer(nil, netAddr)

		// Spin until the peer shows up in the connection manager or until 100 iterations.
		// Note the pause between each iteration.
		for ii := 0; ii < 100; ii++ {
			for _, bitcloutPeer := range fes.backendServer.GetConnectionManager().GetAllPeers() {
				if !strings.Contains(bitcloutPeer.Address(), ip+fmt.Sprintf(":%d", protocolPort)) {
					continue
				}
				// If we get here it means we're dealing with the peer we just connected to.

				// Send a GetHeaders message to the Peer to start the headers sync.
				// Note that we include an empty BlockHash as the stopHash to indicate we want as
				// many headers as the Peer can give us.
				// Note: We don't need to acquire the ChainLock because our parent does it.

				// Grab the ChainLock since we might do a blockchain lookup below.
				locator :=  fes.blockchain.LatestLocator(fes.blockchain.HeaderTip())

				bitcloutPeer.AddBitCloutMessage(&lib.MsgBitCloutGetHeaders{
					StopHash:     &lib.BlockHash{},
					BlockLocator: locator,
				}, false)

				// After sending GetHeaders above, make the peer the syncPeer.
				fes.backendServer.SyncPeer = bitcloutPeer

				// At this point the peer shoud be connected. Add their address to the addrmgr
				// in case the user wants to connect again in the future. Set the source to be
				// the address itself since we don't have anything else.
				fes.backendServer.GetConnectionManager().GetAddrManager().AddAddress(netAddr, netAddr)

				connectPeerDone <- true
				return
			}

			time.Sleep(200 * time.Millisecond)
		}
	}()
	select {
	case <-connectPeerDone:
	case <-time.After(5 * time.Second):
		_AddBadRequestError(ww, fmt.Sprintf("Cannot connect to node %s:%d: %v", ip, protocolPort, err))
		return
	}

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be connected.
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) _handleDisconnectBitCloutNode(
	ww http.ResponseWriter, ip string, port uint16) {

	// Get all the peers from the connection manager and try and find one
	// that has a matching IP.
	var peerFound *lib.Peer
	for _, bitcloutPeer := range fes.backendServer.GetConnectionManager().GetAllPeers() {
		if strings.Contains(bitcloutPeer.Address(), ip+fmt.Sprintf(":%d", port)) {
			peerFound = bitcloutPeer
			break
		}
	}
	if peerFound == nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"Peer with IP %s not found in connected peer list. Are you sure "+
				"you are connected to this peer?", ip))
		return
	}

	// Manually remove the peer from the connection manager and mark it as such
	// so that the connection manager won't reconnect to it or replace it.
	fes.backendServer.GetConnectionManager().RemovePeer(peerFound)
	peerFound.PeerManuallyRemovedFromConnectionManager = true

	peerFound.Disconnect()

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be connected.
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) _handleChangeBitcoinSyncPeer(ww http.ResponseWriter, newPeerAddr string) {
	// Let it block. We want to wait for the response.
	replyChan := make(chan error)
	fes.backendServer.GetBitcoinManager().SwitchPeerChan <- &lib.SwitchPeerMsg{
		NewAddr:   newPeerAddr,
		ReplyChan: replyChan,
	}
	err := <-replyChan
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("Problem connecting to new peer %s: %v", newPeerAddr, err))
		return
	}

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be connected.
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

// NodeControl ...
func (fes *APIServer) NodeControl(ww http.ResponseWriter, req *http.Request) {
	// This function doesn't change anything on the user object so no need to lock.
	//fes.DataLock.Lock()
	//defer fes.DataLock.Unlock()

	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := NodeControlRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControlRequest: Problem parsing request body: %v", err))
		return
	}

	allowedOperationTypes := make(map[string]bool)
	allowedOperationTypes["get_info"] = true
	allowedOperationTypes["connect_bitclout_node"] = true
	allowedOperationTypes["disconnect_bitclout_node"] = true
	allowedOperationTypes["connect_bitcoin_node"] = true
	allowedOperationTypes["update_miner"] = true

	if _, isOperationTypeAllowed := allowedOperationTypes[requestData.OperationType]; !isOperationTypeAllowed {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControlRequest: OperationType %s is not allowed. Allowed types are: %v",
			requestData.OperationType, allowedOperationTypes))
		return
	}

	if requestData.OperationType == "get_info" {
		fes._handleNodeControlGetInfo(&requestData, ww)
		return

	} else if requestData.OperationType == "connect_bitclout_node" {
		ip, port := parseIPAndPort(requestData.Address)
		fes._handleConnectBitCloutNode(ww, ip, port)
		return

	} else if requestData.OperationType == "disconnect_bitclout_node" {
		ip, port := parseIPAndPort(requestData.Address)
		fes._handleDisconnectBitCloutNode(ww, ip, port)
		return

	} else if requestData.OperationType == "connect_bitcoin_node" {
		fes._handleChangeBitcoinSyncPeer(ww, requestData.Address)
		return

	} else if requestData.OperationType == "update_miner" {
		// Parse the miner public keys into a list of *btcec.PublicKey
		minerPublicKeys := []*btcec.PublicKey{}
		if requestData.MinerPublicKeys != "" {
			pkStrings := strings.Split(requestData.MinerPublicKeys, ",")
			for _, pkStr := range pkStrings {
				publicKeyBytes, _, err := lib.Base58CheckDecode(pkStr)
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("NodeControlRequest: Problem decoding miner public key from base58 %s: %v", pkStr, err))
					return
				}
				pk, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
				if err != nil {
					_AddBadRequestError(ww, fmt.Sprintf("NodeControlRequest: Problem parsing miner public key %s: %v", pkStr, err))
					return
				}

				minerPublicKeys = append(minerPublicKeys, pk)
			}
		}
		fes.backendServer.GetMiner().PublicKeys = minerPublicKeys

	} else {
		_AddBadRequestError(ww, fmt.Sprintf(
			"NodeControlRequest: OperationType %s is allowed but not implemented; "+
				"this should never happen", requestData.OperationType))
		return
	}
}

type ReprocessBitcoinBlockResponse struct {
	Message string
}

func ReprocessBitcoinBlockUsingAPI(blockHeightOrHash string, bitcoinManager *lib.BitcoinManager, params *lib.BitCloutParams) error {

	URL := fmt.Sprintf("https://blockchain.info/rawblock/%v?format=hex", blockHeightOrHash)
	glog.Debugf("ReprocessBitcoinBlockUsingAPI: URL: %v", URL)

	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return fmt.Errorf("ReprocessBitcoinBlockUsingAPI: Problem with req: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ReprocessBitcoinBlockUsingAPI: Problem with HTTP request %s: %v", URL, err)
	}
	defer resp.Body.Close()

	// Read in the response. It should be the hex of a Bitcoin block.
	bodyHexBB, _ := ioutil.ReadAll(resp.Body)
	bodyHex := string(bodyHexBB)
	if resp.StatusCode != 200 {
		return fmt.Errorf("ReprocessBitcoinBlockUsingAPI: Error code from Bitcoin API: %v, %v", resp.StatusCode, bodyHexBB)
	}

	bodyBytes, _ := hex.DecodeString(bodyHex)
	// Ensure there is an error due to deserializing the block.
	var msgBlock wire.MsgBlock
	err = msgBlock.BtcDecode(
		bytes.NewReader(bodyBytes), params.BitcoinProtocolVersion, wire.WitnessEncoding)
	if err != nil {
		return fmt.Errorf("ReprocessBitcoinBlockUsingAPI: Error parsing body: %v, %v, %v", URL, err, bodyHex)
	}

	glog.Infof("Got Bitcoin block to reprocess: %v", msgBlock.BlockHash())
	bitcoinManager.ProcessBitcoinBlock(&msgBlock)

	return nil
}

// ReprocessBitcoinBlock ...
func (fes *APIServer) ReprocessBitcoinBlock(ww http.ResponseWriter, req *http.Request) {
	// Parse all the vars from the URL
	vars := mux.Vars(req)
	blockHashHexOrHeight, blockHashHexOrHeightExists := vars["blockHashHexOrblockHeight"]
	if !blockHashHexOrHeightExists {
		_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Missing block hash hex or height parameter after the slash. "+
			"Usage: curl localhost:8080/reprocess-bitcoin-block/<block hash or block height>"))
		return
	}

	res := &ReprocessBitcoinBlockResponse{}
	// If the parameter has the length of a Bitcoin block hash then we interpret it as such.
	if len(blockHashHexOrHeight) == lib.HashSizeBytes*2 {
		hash, err := chainhash.NewHashFromStr(blockHashHexOrHeight)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Problem decoding block hash hex: %v", err))
			return
		}

		glog.Tracef("ReprocessBitcoinBlock: Requesting Bitcoin block with hash: %v", hash)
		fes.backendServer.GetBitcoinManager().RequestBitcoinBlock(*hash)

		res.Message = fmt.Sprintf("Requested block %v for reprocessing", hash)
	} else {
		// If the parameter does not look like a block hash then we interpret it as a block
		// height.
		blockHeight, err := strconv.Atoi(blockHashHexOrHeight)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Problem decoding block height: %v", err))
			return
		}

		// Subtract off the start block height
		blockHeight -= int(fes.Params.BitcoinStartBlockNode.Height)

		if blockHeight < 0 || int64(blockHeight) > int64(fes.backendServer.GetBitcoinManager().HeaderTip().Height) {
			_AddBadRequestError(ww, fmt.Sprintf(
				"ReprocessBitcoinBlock: Height provided is less than zero or exceeds "+
					"maximum height known, which is %d", blockHeight))
			return
		}

		blockNode := fes.backendServer.GetBitcoinManager().HeaderAtHeight(uint32(blockHeight))
		if blockNode == nil {
			_AddBadRequestError(ww, fmt.Sprintf(
				"ReprocessBitcoinBlock: Did not find Bitcoin block with height: %d", blockHeight))
			return
		}
		fes.backendServer.GetBitcoinManager().RequestBitcoinBlock((chainhash.Hash)(*blockNode.Hash))

		res.Message = fmt.Sprintf("Requested block %v with height %d for reprocessing", (chainhash.Hash)(*blockNode.Hash), blockHeight)
	}

	if err := ReprocessBitcoinBlockUsingAPI(blockHashHexOrHeight, fes.backendServer.GetBitcoinManager(), fes.Params); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Error processing Bitcoin block from API: %v", err))
		return
	}

	// Return the response.
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("ReprocessBitcoinBlock: Problem encoding response as JSON: %v", err))
		return
	}
}

// AdminGetMempoolStatsRequest...
type AdminGetMempoolStatsRequest struct{}

// AdminGetMempoolStatsResponse ...
type AdminGetMempoolStatsResponse struct {
	TransactionSummaryStats map[string]*lib.SummaryStats
}

// AdminGetMempoolStats ...
func (fes *APIServer) AdminGetMempoolStats(ww http.ResponseWriter, req *http.Request) {
	// Grab the summary stats from the mempool.
	transactionSummaryStats := fes.backendServer.GetMempool().GetMempoolSummaryStats()

	res := AdminGetMempoolStatsResponse{
		TransactionSummaryStats: transactionSummaryStats,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminGetMempoolStats: Problem encoding response as JSON: %v", err))
		return
	}
}

type EvictUnminedBitcoinTxnsRequest struct {
	BitcoinTxnHashes []string
	DryRun bool
}

type EvictUnminedBitcoinTxnsResponse struct {
	TotalMempoolTxns int64
	MempoolTxnsLeftAfterEviction int64
	TxnTypesEvicted map[string]int64
	TxnHashesEvicted []string

	UnminedBitcoinExchangeTxns []string
}

func (fes *APIServer) EvictUnminedBitcoinTxns(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := EvictUnminedBitcoinTxnsRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("EvictUnminedBitcoinTxns: Problem parsing request body: %v", err))
		return
	}

	totalMempoolTxns := fes.mempool.Count()
	newPoolCount, evictedTxnsMap, evictedTxnsList, unminedBitcoinExchangeTxns :=
		fes.mempool.EvictUnminedBitcoinTransactions(requestData.BitcoinTxnHashes, requestData.DryRun)

	res := EvictUnminedBitcoinTxnsResponse{
		TotalMempoolTxns: int64(totalMempoolTxns),
		MempoolTxnsLeftAfterEviction:  newPoolCount,
		TxnTypesEvicted: evictedTxnsMap,
		TxnHashesEvicted: evictedTxnsList,

		UnminedBitcoinExchangeTxns: unminedBitcoinExchangeTxns,
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("EvictUnminedBitcoinTxns: Problem encoding response as JSON: %v", err))
		return
	}
}
