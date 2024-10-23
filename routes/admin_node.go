package routes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/deso-protocol/core/lib"
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

type RemoteNodeResponse struct {
	// The latest block height the validator is at.
	LatestBlockHeight uint64

	// RemoteNodeStatus is the string representation of the RemoteNode's status.
	RemoteNodeStatus string

	// PeerResponse is the IP and port of the peer the validator is connected to.
	PeerResponse *PeerResponse

	// PeerConnected is a boolean indicating whether the peer is connected.
	PeerConnected bool

	// ValidatorResponse is the ValidatorEntry converted to a human-readable response.
	ValidatorResponse *ValidatorResponse

	// IsValidator is a boolean indicating whether the remote node is a validator.
	IsValidator bool
}

// NodeControlResponse ...
type NodeControlResponse struct {
	// The current status the DeSo node is at in terms of syncing the DeSo
	// chain.
	DeSoStatus *NodeStatusResponse

	DeSoOutboundPeers    []*PeerResponse
	DeSoInboundPeers     []*PeerResponse
	DeSoUnconnectedPeers []*PeerResponse

	RemoteNodeConnections []*RemoteNodeResponse

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
	desoChainState := fes.blockchain.ChainState()
	desoHeaderTip := fes.blockchain.HeaderTip()
	desoBlockTip := fes.blockchain.BlockTip()

	// Compute the fields for the DeSo NodeStatusResponse
	desoNodeStatus := &NodeStatusResponse{}
	desoNodeStatus.State = desoChainState.String()

	// Main header chain fields
	{
		desoNodeStatus.LatestHeaderHeight = desoHeaderTip.Height
		desoNodeStatus.LatestHeaderHash = hex.EncodeToString(desoHeaderTip.Hash[:])
		desoNodeStatus.LatestHeaderTstampSecs = uint32(desoHeaderTip.Header.GetTstampSecs())
	}
	// Main block chain fields
	{
		desoNodeStatus.LatestBlockHeight = desoBlockTip.Height
		desoNodeStatus.LatestBlockHash = hex.EncodeToString(desoBlockTip.Hash[:])
		desoNodeStatus.LatestBlockTstampSecs = uint32(desoBlockTip.Header.GetTstampSecs())
	}
	if fes.TXIndex != nil {
		// TxIndex status
		desoNodeStatus.LatestTxIndexHeight = fes.TXIndex.TXIndexChain.BlockTip().Height
	}
	// We only have headers remaining if we're in this state.
	if desoChainState == lib.SyncStateSyncingHeaders {
		desoNodeStatus.HeadersRemaining = uint32(
			(time.Now().Unix() - int64(desoNodeStatus.LatestHeaderTstampSecs)) /
				int64(fes.Params.TimeBetweenBlocks.Seconds()))
	}
	// We only have blocks remaining if we're in one of the following states.
	if desoChainState == lib.SyncStateSyncingHeaders ||
		desoChainState == lib.SyncStateSyncingBlocks ||
		desoChainState == lib.SyncStateNeedBlocksss {

		desoNodeStatus.BlocksRemaining = desoHeaderTip.Height - desoBlockTip.Height
	}

	// Get and sort the peers so we have a consistent ordering.
	allDeSoPeers := fes.backendServer.GetConnectionManager().GetAllPeers()
	sort.Slice(allDeSoPeers, func(ii, jj int) bool {
		// Use a hash to get a random but deterministic ordering.
		return allDeSoPeers[ii].Address() < allDeSoPeers[jj].Address()
	})

	// Rack up the inbound and outbound peers from the connection manager.
	desoOutboundPeers := []*PeerResponse{}
	desoInboundPeers := []*PeerResponse{}
	desoUnconnectedPeers := []*PeerResponse{}
	existingDeSoPeers := make(map[string]bool)
	syncPeer := fes.backendServer.SyncPeer
	for _, desoPeer := range allDeSoPeers {
		isSyncPeer := false
		if syncPeer != nil && (desoPeer.String() == syncPeer.String()) {
			isSyncPeer = true
		}
		currentPeerRes := &PeerResponse{
			IP:           desoPeer.IP(),
			ProtocolPort: desoPeer.Port(),
			IsSyncPeer:   isSyncPeer,
		}
		if desoPeer.IsOutbound() {
			desoOutboundPeers = append(desoOutboundPeers, currentPeerRes)
		} else {
			desoInboundPeers = append(desoInboundPeers, currentPeerRes)
		}

		existingDeSoPeers[currentPeerRes.IP+fmt.Sprintf(":%d", currentPeerRes.ProtocolPort)] = true
	}
	// Return some deso addrs from the addr manager.
	desoAddrs := fes.backendServer.AddrMgr.AddressCache()
	sort.Slice(desoAddrs, func(ii, jj int) bool {
		// Use a hash to get a random but deterministic ordering.
		hashI := string(lib.Sha256DoubleHash([]byte(desoAddrs[ii].ToLegacy().IP.String() + fmt.Sprintf(":%d", desoAddrs[ii].Port)))[:])
		hashJ := string(lib.Sha256DoubleHash([]byte(desoAddrs[jj].ToLegacy().IP.String() + fmt.Sprintf(":%d", desoAddrs[jj].Port)))[:])

		return hashI < hashJ
	})
	for _, netAddr := range desoAddrs {
		if len(desoUnconnectedPeers) >= 250 {
			break
		}
		addr := netAddr.ToLegacy().IP.String() + fmt.Sprintf(":%d", netAddr.Port)
		if _, exists := existingDeSoPeers[addr]; exists {
			continue
		}
		desoUnconnectedPeers = append(desoUnconnectedPeers, &PeerResponse{
			IP:           netAddr.ToLegacy().IP.String(),
			ProtocolPort: netAddr.Port,
			// Unconnected peers are not sync peers so leave it set to false.
		})
	}

	// Encode the miner public keys as strings.
	minerPublicKeyStrs := []string{}
	for _, publicKey := range fes.backendServer.GetMiner().PublicKeys {
		minerPublicKeyStrs = append(minerPublicKeyStrs, lib.PkToString(
			publicKey.SerializeCompressed(), fes.Params))
	}

	// Get the network manager connections
	networkManagerConnections := fes.backendServer.GetNetworkManagerConnections()
	uncommittedTipView, err := fes.backendServer.GetBlockchain().GetUncommittedTipView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem getting uncommitted tip view: %v", err))
		return
	}
	remoteNodeConnections := make([]*RemoteNodeResponse, 0)
	for _, connection := range networkManagerConnections {
		remoteNodeConnection, err := _remoteNodeToResponse(connection, uncommittedTipView, fes.Params)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem getting remote node response: %v", err))
			return
		}
		remoteNodeConnections = append(remoteNodeConnections, remoteNodeConnection)
	}

	res := NodeControlResponse{
		DeSoStatus: desoNodeStatus,

		DeSoOutboundPeers:    desoOutboundPeers,
		DeSoInboundPeers:     desoInboundPeers,
		DeSoUnconnectedPeers: desoUnconnectedPeers,

		MinerPublicKeys: minerPublicKeyStrs,

		RemoteNodeConnections: remoteNodeConnections,
	}
	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("NodeControl: Problem encoding response as JSON: %v", err))
		return
	}
}

func _remoteNodeToResponse(remoteNode *lib.RemoteNode, utxoView *lib.UtxoView, params *lib.DeSoParams) (*RemoteNodeResponse, error) {
	remoteNodeResponse := &RemoteNodeResponse{}

	// If the remote node connection has been attempted but a peer hasn't been attached yet, there is no peer
	// information to return.
	peer := remoteNode.GetPeer()
	if peer != nil {
		remoteNodeResponse.PeerResponse = &PeerResponse{
			IP:           remoteNode.GetPeer().IP(),
			ProtocolPort: remoteNode.GetPeer().Port(),
		}
	}

	remoteNodeResponse.RemoteNodeStatus = remoteNode.GetStatus().String()
	remoteNodeResponse.PeerConnected = peer != nil && remoteNode.GetPeer().Connected()
	remoteNodeResponse.IsValidator = remoteNode.IsValidator()
	remoteNodeResponse.LatestBlockHeight = remoteNode.GetLatestBlockHeight()
	if remoteNodeResponse.IsValidator {
		blsPublicKeyPKIDPairEntry, err := utxoView.GetBLSPublicKeyPKIDPairEntry(remoteNode.GetValidatorPublicKey())
		if err != nil {
			return nil, fmt.Errorf("_remoteNodeToResponse: Problem getting BLS public key PKID pair entry: %v", err)
		}
		// If the node identified itself as a validator but it does not have a validator entry in the UtxoView,
		// then it is not a registered validator. We should not return a ValidatorResponse in this case.
		if blsPublicKeyPKIDPairEntry == nil {
			return remoteNodeResponse, nil
		}
		validatorEntry, err := utxoView.GetValidatorByPKID(blsPublicKeyPKIDPairEntry.PKID)
		if err != nil {
			return nil, fmt.Errorf("_remoteNodeToResponse: Problem getting validator entry: %v", err)
		}
		remoteNodeResponse.ValidatorResponse = _convertValidatorEntryToResponse(utxoView, validatorEntry, params)
	}
	return remoteNodeResponse, nil
}

func (fes *APIServer) _handleConnectDeSoNode(
	ww http.ResponseWriter, ip string, protocolPort uint16) {

	// Don't connect to the peer if we're already aware of them.
	for _, desoPeer := range fes.backendServer.GetConnectionManager().GetAllPeers() {
		if strings.Contains(desoPeer.Address(), ip+fmt.Sprintf(":%d", protocolPort)) {
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
		netAddr, err := fes.backendServer.AddrMgr.HostToNetAddress(ip, protocolPort, 0)
		if err != nil {
			_AddBadRequestError(ww, fmt.Sprintf("_handleConnectDeSoNode: Cannot connect to node %s:%d: %v", ip, protocolPort, err))
			return
		}
		fes.backendServer.GetNetworkManager().CreateNonValidatorOutboundConnection(ip)

		// Spin until the peer shows up in the connection manager or until 100 iterations.
		// Note the pause between each iteration.
		for ii := 0; ii < 100; ii++ {
			for _, desoPeer := range fes.backendServer.GetConnectionManager().GetAllPeers() {
				if !strings.Contains(desoPeer.Address(), ip+fmt.Sprintf(":%d", protocolPort)) {
					continue
				}
				// If we get here it means we're dealing with the peer we just connected to.

				// Send a GetHeaders message to the Peer to start the headers sync.
				// Note that we include an empty BlockHash as the stopHash to indicate we want as
				// many headers as the Peer can give us.
				// Note: We don't need to acquire the ChainLock because our parent does it.

				// Grab the ChainLock since we might do a blockchain lookup below.
				locator := fes.blockchain.LatestLocator(fes.blockchain.HeaderTip())

				desoPeer.AddDeSoMessage(&lib.MsgDeSoGetHeaders{
					StopHash:     &lib.BlockHash{},
					BlockLocator: locator,
				}, false)

				// After sending GetHeaders above, make the peer the syncPeer.
				fes.backendServer.SyncPeer = desoPeer

				// At this point the peer shoud be connected. Add their address to the addrmgr
				// in case the user wants to connect again in the future. Set the source to be
				// the address itself since we don't have anything else.
				fes.backendServer.AddrMgr.AddAddress(netAddr, netAddr)

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

func (fes *APIServer) _handleDisconnectDeSoNode(
	ww http.ResponseWriter, ip string, port uint16) {

	// Get all the peers from the connection manager and try and find one
	// that has a matching IP.
	var peerFound *lib.Peer
	for _, desoPeer := range fes.backendServer.GetConnectionManager().GetAllPeers() {
		if strings.Contains(desoPeer.Address(), ip+fmt.Sprintf(":%d", port)) {
			peerFound = desoPeer
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
	remoteNode := fes.backendServer.GetNetworkManager().GetRemoteNodeFromPeer(peerFound)
	if remoteNode != nil {
		fes.backendServer.GetNetworkManager().Disconnect(remoteNode, "admin requested disconnect")
	}

	res := NodeControlResponse{
		// Return an empty response, which indicates we set the peer up to be disconnected.
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
	allowedOperationTypes["connect_deso_node"] = true
	allowedOperationTypes["disconnect_deso_node"] = true
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

	} else if requestData.OperationType == "connect_deso_node" {
		ip, port := parseIPAndPort(requestData.Address)
		fes._handleConnectDeSoNode(ww, ip, port)
		return

	} else if requestData.OperationType == "disconnect_deso_node" {
		ip, port := parseIPAndPort(requestData.Address)
		fes._handleDisconnectDeSoNode(ww, ip, port)
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
				pk, err := btcec.ParsePubKey(publicKeyBytes)
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

type AdminUpdateViewNumberRequest struct {
	ViewNumber uint64
}

func (fes *APIServer) AdminUpdateViewNumber(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := AdminUpdateViewNumberRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateViewNumber: Problem parsing request body: %v", err))
		return
	}

	// Update the view number.
	if err := fes.backendServer.AdminOverrideViewNumber(requestData.ViewNumber); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("AdminUpdateViewNumber: Problem updating view number: %v", err))
		return
	}
}
