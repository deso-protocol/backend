package routes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/bitclout/backend/config"
	"github.com/bitclout/core/lib"
	chainlib "github.com/btcsuite/btcd/blockchain"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	globalStateSharedSecret  = "abcdef"
	testJSONPort             = uint16(17001)
	testMinFeeRateNanosPerKB = uint64(1000)

	// go run transaction_util.go --manual_entropy_hex=0,1
	senderPkString      = "tBCKXFJEDSF7Thcc6BUBcB6kicE5qzmLbAtvFf9LfKSXN4LwFt36oX"
	senderPrivString    = "tbc31669t2YuZ2mi1VLtK6a17RXFPdsuBDcenPLc1eU1ZVRHF9Zv4"
	recipientPkString   = "tBCKXU8pf7nkn8M38sYJeAwiBP7HbSJWy9Zmn4sHNL6gA6ahkriymq"
	recipientPrivString = "tbc24UM432ikvtmyv4zus7HomtUYkxNg3B3HusSLghVxoQXKi9QjZ"

	moneyPkString   = "tBCKVUCQ9WxpVmNthS2PKfY1BCxG4GkWvXqDhQ4q3zLtiwKVUNMGYS"
	moneyPrivString = "tbc2yg6BS7we86H8WUF2xSAmnyJ1x63ZqXaiDkE2mostsxpfmCZiB"

	blockSignerSeed = "essence camp ghost remove document vault ladder swim pupil index apart ring"
	blockSignerPk   = "BC1YLiQ86kwXUy3nfK391xht7N72UmbFY6bGrUsds1A7QKZrs4jJsxo"
)

func GetTestBadgerDb() (_db *badger.DB, _dir string) {
	dir, err := ioutil.TempDir("", "badgerdb")
	if err != nil {
		log.Fatal(err)
	}

	// Open a badgerdb in a temporary directory.
	opts := badger.DefaultOptions(dir)
	opts.Dir = dir
	opts.ValueDir = dir
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
	}

	return db, dir
}

func NewLowDifficultyBlockchain() (*lib.Blockchain, *lib.BitCloutParams, *badger.DB) {

	// Set the number of txns per view regeneration to one while creating the txns
	lib.ReadOnlyUtxoViewRegenerationIntervalTxns = 1

	return NewLowDifficultyBlockchainWithParams(&lib.BitCloutTestnetParams)
}

func NewLowDifficultyBlockchainWithParams(params *lib.BitCloutParams) (
	*lib.Blockchain, *lib.BitCloutParams, *badger.DB) {

	// Set the number of txns per view regeneration to one while creating the txns
	lib.ReadOnlyUtxoViewRegenerationIntervalTxns = 1

	db, _ := GetTestBadgerDb()
	timesource := chainlib.NewMedianTime()

	// Set some special parameters for testing. If the blocks above are changed
	// these values should be updated to reflect the latest testnet values.
	paramsCopy := *params
	paramsCopy.GenesisBlock = &lib.MsgBitCloutBlock{
		Header: &lib.MsgBitCloutHeader{
			Version:               0,
			PrevBlockHash:         lib.MustDecodeHexBlockHash("0000000000000000000000000000000000000000000000000000000000000000"),
			TransactionMerkleRoot: lib.MustDecodeHexBlockHash("097158f0d27e6d10565c4dc696c784652c3380e0ff8382d3599a4d18b782e965"),
			TstampSecs:            uint64(1560735050),
			Height:                uint64(0),
			Nonce:                 uint64(0),
			// No ExtraNonce is set in the genesis block
		},
		Txns: []*lib.MsgBitCloutTxn{
			{
				TxInputs:  []*lib.BitCloutInput{},
				TxOutputs: []*lib.BitCloutOutput{},
				TxnMeta: &lib.BlockRewardMetadataa{
					ExtraData: []byte("They came here, to the new world. World 2.0, version 1776."),
				},
				// A signature is not required for BLOCK_REWARD transactions since they
				// don't spend anything.
			},
		},
	}
	paramsCopy.MinDifficultyTargetHex = "999999948931e5874cf66a74c0fda790dd8c7458243d400324511a4c71f54faa"
	paramsCopy.MinChainWorkHex = "0000000000000000000000000000000000000000000000000000000000000000"
	paramsCopy.MiningIterationsPerCycle = 500
	// Set maturity to 2 blocks so we can test spending on short chains. The
	// tests rely on the maturity equaling exactly two blocks (i.e. being
	// two times the time between blocks).
	paramsCopy.TimeBetweenBlocks = 2 * time.Second
	paramsCopy.BlockRewardMaturity = time.Second * 4
	paramsCopy.TimeBetweenDifficultyRetargets = 100 * time.Second
	paramsCopy.MaxDifficultyRetargetFactor = 2
	paramsCopy.SeedBalances = []*lib.BitCloutOutput{
		{
			PublicKey:   lib.MustBase58CheckDecode(moneyPkString),
			AmountNanos: uint64(2000000 * lib.NanosPerUnit),
		},
	}

	// Temporarily modify the seed balances to make a specific public
	// key have some BitClout
	chain, err := lib.NewBlockchain([]string{blockSignerPk}, 0,
		&paramsCopy, timesource, db, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	return chain, &paramsCopy, db
}

func NewTestMiner(t *testing.T, chain *lib.Blockchain, params *lib.BitCloutParams, isSender bool) (*lib.BitCloutMempool, *lib.BitCloutMiner) {
	assert := assert.New(t)
	require := require.New(t)
	_ = assert
	_ = require

	mempool := lib.NewBitCloutMempool(
		chain, 0, /* rateLimitFeeRateNanosPerKB */
		0 /* minFeeRateNanosPerKB */, "", true,
		"" /*dataDir*/, "")
	minerPubKeys := []string{}
	if isSender {
		minerPubKeys = append(minerPubKeys, senderPkString)
	} else {
		minerPubKeys = append(minerPubKeys, recipientPkString)
	}

	blockProducer, err := lib.NewBitCloutBlockProducer(
		0, 1,
		blockSignerSeed,
		mempool, chain,
		nil, params)
	require.NoError(err)

	newMiner, err := lib.NewBitCloutMiner(minerPubKeys, 1 /*numThreads*/, blockProducer, params)
	require.NoError(err)
	return mempool, newMiner
}

func newTestAPIServer(t *testing.T, globalStateRemoteNode string) (*APIServer, *APIServer, *lib.BitCloutMiner) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	chain, params, _ := NewLowDifficultyBlockchain()
	txIndexDb, _ := GetTestBadgerDb()
	txIndex, _ := lib.NewTXIndex(chain, nil, params, txIndexDb.Opts().Dir)
	mempool, miner := NewTestMiner(t, chain, params, true /*isSender*/)
	// Mine two blocks to give the sender some BitClout.
	block1, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	block2, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, mempool)
	require.NoError(err)
	_, _, _ = block1, block2, mempool

	// Create a global state db only if a remote node was not provided
	var globalStateDB *badger.DB
	if globalStateRemoteNode == "" {
		globalStateDB, _ = GetTestBadgerDb()
	}
	publicConfig := &config.Config{
		APIPort:                 testJSONPort,
		GlobalStateRemoteNode:   globalStateRemoteNode,
		GlobalStateRemoteSecret: globalStateSharedSecret,
	}
	publicApiServer, err := NewAPIServer(
		nil, mempool, chain, miner.BlockProducer, txIndex, params, publicConfig,
		2000, globalStateDB, nil, "")
	require.NoError(err)

	// Calling initState() initializes the state of the APIServer and the router as well.
	publicApiServer.initState()

	privateConfig := publicConfig
	privateConfig.AdminPublicKeys = []string{"adminpublickey"}
	privateApiServer, err := NewAPIServer(
		nil, mempool, chain, miner.BlockProducer, txIndex, params, privateConfig,
		2000, globalStateDB, nil, "")
	require.NoError(err)

	// Calling initState() initializes the state of the APIServer and the router as well.
	privateApiServer.initState()

	return publicApiServer, privateApiServer, miner
}

func TestAPI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	apiServer, _, miner := newTestAPIServer(t, "" /*globalStateRemoteNode*/)

	{
		request, _ := http.NewRequest("GET", RoutePathAPIBase, nil)
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "OK response is expected")
		assert.Contains(string(response.Body.Bytes()), "Header")
	}

	// Generating a keypair with the proper mnemonic should work and should
	// match the output of BIP39 as computed with the iancoleman tool
	// (https://iancoleman.io/bip39/)
	// Index=0, Mainnet
	{
		// Run this test as mainnet.
		apiServer.Params = &lib.BitCloutMainnetParams
		keyPairRequest := &APIKeyPairRequest{
			Mnemonic:  "elegant express swarm mercy divorce conduct actor brain critic subject fit broom",
			ExtraText: "extra text",
			Index:     0,
		}
		jsonRequest, err := json.Marshal(keyPairRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIKeyPair,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		keyPairResponse := APIKeyPairResponse{}
		if err := decoder.Decode(&keyPairResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", keyPairResponse.Error)
		assert.Equal("028c4dd3905511177d536af8dfb70b30ec51c0a1c7b7327e1c48393fd524f5d09e", keyPairResponse.PublicKeyHex)
		assert.Equal("5f7992dc1efbfa9f188a1c96c613f69f98fbc83857f12033e51eb49530c4ead5", keyPairResponse.PrivateKeyHex)

		assert.Equal("BC1YLgjfMDyes7FkCoWsXYbHxW5h6QNZGLmHdmJaEWzUPd2jRhVZHQT", keyPairResponse.PublicKeyBase58Check)
		assert.Equal("bc6EzXTBvGcciQoTge3Fb43mBVs14FLxW5RjZLebB4QYRdXrd1oEb", keyPairResponse.PrivateKeyBase58Check)

		apiServer.Params = &lib.BitCloutTestnetParams
	}
	// Index=5, Mainnet
	{
		// Run this test as mainnet.
		apiServer.Params = &lib.BitCloutMainnetParams
		keyPairRequest := &APIKeyPairRequest{
			Mnemonic:  "elegant express swarm mercy divorce conduct actor brain critic subject fit broom",
			ExtraText: "extra text",
			Index:     5,
		}
		jsonRequest, err := json.Marshal(keyPairRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIKeyPair,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		keyPairResponse := APIKeyPairResponse{}
		if err := decoder.Decode(&keyPairResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", keyPairResponse.Error)
		assert.Equal("02ea06769d591e5d9df782852cdb0b326d127f3b962fe9beeb23397be4a35d99d3", keyPairResponse.PublicKeyHex)
		assert.Equal("5fa2c03b62119d9bd116faa9e2855e4f8fef0a7d623b9197f3a3bc0204795d1f", keyPairResponse.PrivateKeyHex)
		assert.Equal("BC1YLhSwLFat8r1WW6GgzL41ppeWRVBdwMuAgW9uPnatsG3XnWxR4zV", keyPairResponse.PublicKeyBase58Check)
		assert.Equal("bc6EzbZVTKbZXZBNk39feiAsVKK1WQKcVTzbcwJXHWrcjZ5zHo7D5", keyPairResponse.PrivateKeyBase58Check)

		apiServer.Params = &lib.BitCloutTestnetParams
	}
	// Index=0, Testnet
	{
		keyPairRequest := &APIKeyPairRequest{
			Mnemonic:  "elegant express swarm mercy divorce conduct actor brain critic subject fit broom",
			ExtraText: "extra text",
			Index:     0,
		}
		jsonRequest, err := json.Marshal(keyPairRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIKeyPair,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		keyPairResponse := APIKeyPairResponse{}
		if err := decoder.Decode(&keyPairResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", keyPairResponse.Error)
		assert.Equal("028c4dd3905511177d536af8dfb70b30ec51c0a1c7b7327e1c48393fd524f5d09e", keyPairResponse.PublicKeyHex)
		assert.Equal("5f7992dc1efbfa9f188a1c96c613f69f98fbc83857f12033e51eb49530c4ead5", keyPairResponse.PrivateKeyHex)
		assert.Equal("tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq", keyPairResponse.PublicKeyBase58Check)
		assert.Equal("tbc2BcN1yQkawEpqpyJSkgHg6PDVU5jQADmzn1SkTN64Hv5qQt48m", keyPairResponse.PrivateKeyBase58Check)
	}
	// Index=5, Testnet
	{
		keyPairRequest := &APIKeyPairRequest{
			Mnemonic:  "elegant express swarm mercy divorce conduct actor brain critic subject fit broom",
			ExtraText: "extra text",
			Index:     5,
		}
		jsonRequest, err := json.Marshal(keyPairRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIKeyPair,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		keyPairResponse := APIKeyPairResponse{}
		if err := decoder.Decode(&keyPairResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", keyPairResponse.Error)
		assert.Equal("02ea06769d591e5d9df782852cdb0b326d127f3b962fe9beeb23397be4a35d99d3", keyPairResponse.PublicKeyHex)
		assert.Equal("5fa2c03b62119d9bd116faa9e2855e4f8fef0a7d623b9197f3a3bc0204795d1f", keyPairResponse.PrivateKeyHex)
		assert.Equal("tBCKWaBMRrqYwvSEzr1SNeFdDxXoohQsSeEcDpq8nxhvCxVDcg8Hgf", keyPairResponse.PublicKeyBase58Check)
		assert.Equal("tbc2BgUKWTjXkPCktNQrpLQnQCfVvEi49cLrqc6gZpY8bqdyQywvC", keyPairResponse.PrivateKeyBase58Check)
	}

	// Generate keypairs for an account with no password and no extra text
	{
		// Run this test as mainnet.
		apiServer.Params = &lib.BitCloutMainnetParams
		keyPairRequest := &APIKeyPairRequest{
			Mnemonic: "trial economy dentist mistake engage enact blur segment helmet evoke taste bulb",
			Index:    0,
		}
		jsonRequest, err := json.Marshal(keyPairRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIKeyPair,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		keyPairResponse := APIKeyPairResponse{}
		if err := decoder.Decode(&keyPairResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", keyPairResponse.Error)
		assert.Equal("02e101f8bcd5b663235a4a23f22eb67edb5b7baa592975cc8af2af0edb51771332", keyPairResponse.PublicKeyHex)
		assert.Equal("3d5f4f54497c0fb5af052f0a35384912797a970e681579cdc276e621da69e53a", keyPairResponse.PrivateKeyHex)
		assert.Equal("BC1YLhNxzU7cwo2Vr5xCMWvVsHiWUwB6myo56QDsxfUyiu5cf3UaDVc", keyPairResponse.PublicKeyBase58Check)
		assert.Equal("bc6EjWM6p9C5yPLtNRE9GRpPAJePqT7WsCAFEi51mYULQZfEawjA6", keyPairResponse.PrivateKeyBase58Check)

		apiServer.Params = &lib.BitCloutTestnetParams
	}

	// Generate keypairs for a deep index
	{
		// Run this test as mainnet.
		apiServer.Params = &lib.BitCloutMainnetParams
		keyPairRequest := &APIKeyPairRequest{
			Mnemonic: "trial economy dentist mistake engage enact blur segment helmet evoke taste bulb",
			Index:    1019,
		}
		jsonRequest, err := json.Marshal(keyPairRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIKeyPair,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		keyPairResponse := APIKeyPairResponse{}
		if err := decoder.Decode(&keyPairResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", keyPairResponse.Error)
		assert.Equal("03214295b3cb789fe577330a9d4ad893d8972e60a087ed88715eedabe0fe6cb0f3", keyPairResponse.PublicKeyHex)
		assert.Equal("c7d92190c6d1db3eaa12b0ed109f1670d709c6d73980963f2ce11e306cf83df7", keyPairResponse.PrivateKeyHex)
		assert.Equal("BC1YLhsGETW1BghV5WtddyySZrwVeXvMSUcujD1r6FH2Jggzh87T1Cg", keyPairResponse.PublicKeyBase58Check)
		assert.Equal("bc6FnVXYfBNKD8UN9M8134zUcLEYRiZ14UCvm57BMbM7sbvhxbftg", keyPairResponse.PrivateKeyBase58Check)

		apiServer.Params = &lib.BitCloutTestnetParams
	}

	// The balance of the miner public key should be nonzero and there should
	// be 2 UTXOs associated with it since we mined two blocks.
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: senderPkString,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(2000000000), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(2, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Equal(int64(1000000000), int64(utxoEntry.AmountNanos))
			assert.Contains([]int64{1, 2}, utxoEntry.Confirmations)
			assert.Equal(int64(0), utxoEntry.Index)
			assert.Equal("UtxoTypeBlockReward", utxoEntry.UtxoType)
			assert.Equal(senderPkString, utxoEntry.PublicKeyBase58Check)
		}
	}

	// When Confirmations is set to 2, we should only get one of the UTXOs
	// back from the balance function.
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: senderPkString,
			Confirmations:        2,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(1000000000), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(1, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Equal(int64(1000000000), int64(utxoEntry.AmountNanos))
			assert.Equal(int64(2), utxoEntry.Confirmations)
			assert.Equal(int64(0), utxoEntry.Index)
			assert.Equal("UtxoTypeBlockReward", utxoEntry.UtxoType)
			assert.Equal(senderPkString, utxoEntry.PublicKeyBase58Check)
		}
	}

	// Updating the txindex should work.
	require.NoError(apiServer.TXIndex.Update())
	// Running it a second time shouldn't be problematic.
	require.NoError(apiServer.TXIndex.Update())

	// Getting info on a nonexistent transaction should fail gracefully.
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			TransactionIDBase58Check: lib.PkToString([]byte("12345678901234567890123456789012"), apiServer.Params),
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(400, response.Code, "400 response expected")
		assert.Contains(string(response.Body.Bytes()), "Could not find transaction")
	}
	// Getting info on a nonexistent public key should fail gracefully.
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			PublicKeyBase58Check: "UNG4ZRFtYZAg9r61ZF6jb11ViAzGQ3NxpTP7zvm6292Eu36ut7BpWn",
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		require.Equal(0, len(transactionInfoRes.Transactions))
	}
	// The miner public key should return two transactions, one for each block reward.
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			PublicKeyBase58Check: senderPkString,
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		assert.Equal(2, len(transactionInfoRes.Transactions))
		assert.Contains(
			[]string{
				hex.EncodeToString(apiServer.blockchain.BestChain()[1].Hash[:]),
				hex.EncodeToString(apiServer.blockchain.BestChain()[2].Hash[:]),
			},
			transactionInfoRes.Transactions[0].BlockHashHex)
		assert.Contains(
			[]string{
				hex.EncodeToString(apiServer.blockchain.BestChain()[1].Hash[:]),
				hex.EncodeToString(apiServer.blockchain.BestChain()[2].Hash[:]),
			},
			transactionInfoRes.Transactions[1].BlockHashHex)
		assert.Equal(0, len(transactionInfoRes.Transactions[0].Inputs))
		assert.Equal(1, len(transactionInfoRes.Transactions[0].Outputs))
	}
	// Lookup the info for the first block reward transaction.
	var firstBlockTxn *lib.MsgBitCloutTxn
	var secondBlockTxn *lib.MsgBitCloutTxn
	{
		blockHash := apiServer.blockchain.BestChain()[1].Hash
		blockLookup, err := lib.GetBlock(blockHash, apiServer.blockchain.DB())
		require.NoError(err)
		block2Lookup, err := lib.GetBlock(apiServer.blockchain.BestChain()[2].Hash, apiServer.blockchain.DB())

		firstBlockTxn = blockLookup.Txns[0]
		secondBlockTxn = block2Lookup.Txns[0]

		transactionInfoRequest := &APITransactionInfoRequest{
			TransactionIDBase58Check: lib.PkToString(firstBlockTxn.Hash()[:], apiServer.Params),
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		assert.Equal(1, len(transactionInfoRes.Transactions))
		assert.Contains(
			[]string{
				hex.EncodeToString(apiServer.blockchain.BestChain()[1].Hash[:]),
			},
			transactionInfoRes.Transactions[0].BlockHashHex)
		assert.Equal(0, len(transactionInfoRes.Transactions[0].Inputs))
		assert.Equal(1, len(transactionInfoRes.Transactions[0].Outputs))
		assert.Equal(
			lib.PkToString(firstBlockTxn.TxOutputs[0].PublicKey, apiServer.Params),
			transactionInfoRes.Transactions[0].Outputs[0].PublicKeyBase58Check)
		assert.Equal(
			int64(1000000000),
			int64(transactionInfoRes.Transactions[0].Outputs[0].AmountNanos))
	}

	// Sending BitClout with a bad private key should fail.
	{
		transferBitCloutRequest := &APITransferBitCloutRequest{
			SenderPrivateKeyBase58Check:   "un5aPDDWFUVkbGKFUm6S9ftSPWSpeQhVM4oftYbYJys6dk9XxXh",
			RecipientPublicKeyBase58Check: "UNG4YzvzLe3dKA7S8dA5w5akft13MJfThje5J4pPZStoUPe1CNFcaZ",
			AmountNanos:                   500,
			// AccountName string
			// Password string
			// Index uint32
			// MinFeeRateNanosPerKB
			// DryRun
		}
		jsonRequest, err := json.Marshal(transferBitCloutRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransferBitClout,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(400, response.Code, "400 response expected")
		assert.Contains(string(response.Body.Bytes()), "Problem decoding")
	}

	// Send BitClout from the miner public key to another public key.
	// When DryRun is set to true, the balances shouldn't change.
	apiServer.MinFeeRateNanosPerKB = 2000
	txn1Hex := ""
	{
		transferBitCloutRequest := &APITransferBitCloutRequest{
			SenderPrivateKeyBase58Check: senderPrivString,
			// Account "account2" index 0
			RecipientPublicKeyBase58Check: "tUN2P5LeqFy1ucd2rYdzND7Fgis5zgNuZa69UGsXYcGJPjvvjgXk8P",
			AmountNanos:                   500,
			// AccountName string
			// Password string
			// Index uint32
			// MinFeeRateNanosPerKB
			DryRun: true,
		}
		jsonRequest, err := json.Marshal(transferBitCloutRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransferBitClout,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transferBitCloutResponse := APITransferBitCloutResponse{}
		if err := decoder.Decode(&transferBitCloutResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transferBitCloutResponse.Error)
		assert.Equal(senderPkString,
			transferBitCloutResponse.TransactionInfo.SenderPublicKeyBase58Check)
		assert.Equal("tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
			transferBitCloutResponse.TransactionInfo.RecipientPublicKeyBase58Check)
		assert.Equal(int64(446), int64(transferBitCloutResponse.TransactionInfo.FeeNanos))
		assert.Equal(int64(500), int64(transferBitCloutResponse.TransactionInfo.SpendAmountNanos))
		assert.Equal(int64(1000000000-500-446), int64(transferBitCloutResponse.TransactionInfo.ChangeAmountNanos))
		assert.LessOrEqual(int64(2000), int64(transferBitCloutResponse.TransactionInfo.FeeRateNanosPerKB))
		assert.Equal(int64(1000000000), int64(transferBitCloutResponse.TransactionInfo.TotalInputNanos))
		assert.Equal("BASIC_TRANSFER", transferBitCloutResponse.Transaction.TransactionType)
		assert.Equal(1, len(transferBitCloutResponse.Transaction.Inputs))
		assert.Equal(2, len(transferBitCloutResponse.Transaction.Outputs))
		txn1Hex = transferBitCloutResponse.Transaction.RawTransactionHex
	}
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: senderPkString,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(2000000000), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(2, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Equal(int64(1000000000), int64(utxoEntry.AmountNanos))
			assert.Contains([]int64{1, 2}, utxoEntry.Confirmations)
			assert.Equal(int64(0), utxoEntry.Index)
			assert.Equal("UtxoTypeBlockReward", utxoEntry.UtxoType)
			assert.Equal(senderPkString, utxoEntry.PublicKeyBase58Check)
		}
	}
	// Adding the transaction to the mempool should cause changes to the
	// confirmed and unconfirmed balances.
	txn1 := &lib.MsgBitCloutTxn{}
	txn1Bytes, _ := hex.DecodeString(txn1Hex)
	_ = txn1.FromBytes(txn1Bytes)
	_, err := apiServer.mempool.ProcessTransaction(
		txn1, false /*allowOrphan*/, true /*rateLimit*/, 0, /*peerID*/
		true /*verifySignatures*/)
	require.NoError(err)
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: senderPkString,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(1000000000), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(999999054), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(2, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{0, 1, 2}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal(senderPkString, utxoEntry.PublicKeyBase58Check)
		}
	}
	// The public key we sent to should also have an updated balance.
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: "tUN2P5LeqFy1ucd2rYdzND7Fgis5zgNuZa69UGsXYcGJPjvvjgXk8P",
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(0), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(500), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(1, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{0}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal("tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
				utxoEntry.PublicKeyBase58Check)
		}
	}
	// The MinFeeRatePerKB should be respected. Also send a second transaction
	// to a third public key.
	txn2Hex := ""
	{
		transferBitCloutRequest := &APITransferBitCloutRequest{
			SenderPrivateKeyBase58Check: "tunSFqT5W5enayqKcx9Lqcwep5w85NejpbsMtvjKXZ74f5UVZmULQ",
			// Account "account2" index 0
			RecipientPublicKeyBase58Check: "tUN2PncdrsCHeNPL9JTT9fq81HgR5VTaahyCD8CgpCgn2kjHauD7L6",
			AmountNanos:                   100,
			// AccountName string
			// Password string
			// Index uint32
			MinFeeRateNanosPerKB: 100,
			DryRun:               true,
		}
		jsonRequest, err := json.Marshal(transferBitCloutRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransferBitClout,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transferBitCloutResponse := APITransferBitCloutResponse{}
		if err := decoder.Decode(&transferBitCloutResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transferBitCloutResponse.Error)
		assert.Equal("tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
			transferBitCloutResponse.TransactionInfo.SenderPublicKeyBase58Check)
		assert.Equal("tBCKWaBMRrqYwvSEzr1SNeFdDxXoohQsSeEcDpq8nxhvCxVDcg8Hgf",
			transferBitCloutResponse.TransactionInfo.RecipientPublicKeyBase58Check)
		assert.Equal(int64(22), int64(transferBitCloutResponse.TransactionInfo.FeeNanos))
		assert.Equal(int64(100), int64(transferBitCloutResponse.TransactionInfo.SpendAmountNanos))
		assert.Equal(int64(500-100-22), int64(transferBitCloutResponse.TransactionInfo.ChangeAmountNanos))
		assert.LessOrEqual(int64(100), int64(transferBitCloutResponse.TransactionInfo.FeeRateNanosPerKB))
		assert.Equal(int64(500), int64(transferBitCloutResponse.TransactionInfo.TotalInputNanos))
		assert.Equal("BASIC_TRANSFER", transferBitCloutResponse.Transaction.TransactionType)
		assert.Equal(1, len(transferBitCloutResponse.Transaction.Inputs))
		assert.Equal(2, len(transferBitCloutResponse.Transaction.Outputs))
		txn2Hex = transferBitCloutResponse.Transaction.RawTransactionHex
	}
	txn2 := &lib.MsgBitCloutTxn{}
	txn2Bytes, _ := hex.DecodeString(txn2Hex)
	_ = txn2.FromBytes(txn2Bytes)
	apiServer.mempool.ProcessTransaction(
		txn2, false /*allowOrphan*/, true /*rateLimit*/, 0, /*peerID*/
		true /*verifySignatures*/)
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: "tUN2P5LeqFy1ucd2rYdzND7Fgis5zgNuZa69UGsXYcGJPjvvjgXk8P",
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(0), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(378), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(1, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{0}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal("tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
				utxoEntry.PublicKeyBase58Check)
		}
	}
	// The balance with confirmations=1 should return zero for the
	// new address and 2 for the normal address.
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: "tUN2P5LeqFy1ucd2rYdzND7Fgis5zgNuZa69UGsXYcGJPjvvjgXk8P",
			Confirmations:        1,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(0), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(0, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{0}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal("tUN2P5LeqFy1ucd2rYdzND7Fgis5zgNuZa69UGsXYcGJPjvvjgXk8P",
				utxoEntry.PublicKeyBase58Check)
		}
	}
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: senderPkString,
			Confirmations:        1,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(1000000000), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(1, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{1}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal(senderPkString,
				utxoEntry.PublicKeyBase58Check)
		}
	}

	// The transaction info should be available even for the mempool
	// transactions.
	//
	// The first send from the miner should be available.
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			TransactionIDBase58Check: lib.PkToString(txn1.Hash()[:], apiServer.Params),
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		assert.Equal(1, len(transactionInfoRes.Transactions))
		// Block hash should be empty since this transaction is in the mempool.
		assert.Equal(
			"0000000000000000000000000000000000000000000000000000000000000000",
			transactionInfoRes.Transactions[0].BlockHashHex)
		assert.Equal(1, len(transactionInfoRes.Transactions[0].Inputs))
		assert.Contains(
			[]string{
				lib.PkToString(firstBlockTxn.Hash()[:], apiServer.Params),
				lib.PkToString(secondBlockTxn.Hash()[:], apiServer.Params),
			},
			transactionInfoRes.Transactions[0].Inputs[0].TransactionIDBase58Check)
		assert.Equal(2, len(transactionInfoRes.Transactions[0].Outputs))
		assert.Contains(
			[]string{
				senderPkString,
				"tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
			},
			transactionInfoRes.Transactions[0].Outputs[0].PublicKeyBase58Check)
		assert.Contains(
			[]string{
				senderPkString,
				"tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
			},
			transactionInfoRes.Transactions[0].Outputs[1].PublicKeyBase58Check)
	}
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			TransactionIDBase58Check: lib.PkToString(txn2.Hash()[:], apiServer.Params),
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		assert.Equal(1, len(transactionInfoRes.Transactions))
		// Block hash should be empty since this transaction is in the mempool.
		assert.Equal(
			"0000000000000000000000000000000000000000000000000000000000000000",
			transactionInfoRes.Transactions[0].BlockHashHex)
		assert.Equal(1, len(transactionInfoRes.Transactions[0].Inputs))
		assert.Contains(
			lib.PkToString(txn1.Hash()[:], apiServer.Params),
			transactionInfoRes.Transactions[0].Inputs[0].TransactionIDBase58Check)
		assert.Equal(2, len(transactionInfoRes.Transactions[0].Outputs))
	}

	// Mine a block and check the balances.
	block3, err := miner.MineAndProcessSingleBlock(0 /*threadIndex*/, apiServer.mempool)
	require.NoError(err)
	balSum := int64(0)
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: senderPkString,
			Confirmations:        1,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		balSum += balanceResponse.ConfirmedBalanceNanos
		assert.Equal(int64(2999999522), balanceResponse.ConfirmedBalanceNanos)
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(3, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{1, 2}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal(senderPkString,
				utxoEntry.PublicKeyBase58Check)
		}
	}
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: "tUN2P5LeqFy1ucd2rYdzND7Fgis5zgNuZa69UGsXYcGJPjvvjgXk8P",
			Confirmations:        1,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(378), balanceResponse.ConfirmedBalanceNanos)
		balSum += balanceResponse.ConfirmedBalanceNanos
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(1, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{1}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal("tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
				utxoEntry.PublicKeyBase58Check)
		}
	}
	{
		balanceRequest := &APIBalanceRequest{
			PublicKeyBase58Check: "tUN2PncdrsCHeNPL9JTT9fq81HgR5VTaahyCD8CgpCgn2kjHauD7L6",
			Confirmations:        1,
		}
		jsonRequest, err := json.Marshal(balanceRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPIBalance,
			bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		// Check the values of the response
		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		balanceResponse := APIBalanceResponse{}
		if err := decoder.Decode(&balanceResponse); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", balanceResponse.Error)
		assert.Equal(int64(100), balanceResponse.ConfirmedBalanceNanos)
		balSum += balanceResponse.ConfirmedBalanceNanos
		assert.Equal(int64(0), balanceResponse.UnconfirmedBalanceNanos)
		assert.Equal(1, len(balanceResponse.UTXOs))
		for _, utxoEntry := range balanceResponse.UTXOs {
			assert.Contains([]int64{1}, utxoEntry.Confirmations)
			assert.Contains([]int64{0, 1}, utxoEntry.Index)
			assert.Equal("tBCKWaBMRrqYwvSEzr1SNeFdDxXoohQsSeEcDpq8nxhvCxVDcg8Hgf",
				utxoEntry.PublicKeyBase58Check)
		}
	}

	// The transactions should have their block hashes set when queried
	// now.
	require.NoError(apiServer.TXIndex.Update())
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			TransactionIDBase58Check: lib.PkToString(txn1.Hash()[:], apiServer.Params),
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		assert.Equal(1, len(transactionInfoRes.Transactions))
		// Block hash should be empty since this transaction is in the mempool.
		block3Hash, _ := block3.Hash()
		assert.Equal(
			hex.EncodeToString(block3Hash[:]),
			transactionInfoRes.Transactions[0].BlockHashHex)
		assert.Equal(1, len(transactionInfoRes.Transactions[0].Inputs))
		assert.Contains(
			[]string{
				lib.PkToString(firstBlockTxn.Hash()[:], apiServer.Params),
				lib.PkToString(secondBlockTxn.Hash()[:], apiServer.Params),
			},
			transactionInfoRes.Transactions[0].Inputs[0].TransactionIDBase58Check)
		assert.Equal(2, len(transactionInfoRes.Transactions[0].Outputs))
		assert.Contains(
			[]string{
				senderPkString,
				"tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
			},
			transactionInfoRes.Transactions[0].Outputs[0].PublicKeyBase58Check)
		assert.Contains(
			[]string{
				senderPkString,
				"tBCKVruNQFcHDAfwi6BybBXkuPiUitLCRWMZUyVyXNHSZwgrpF2Leq",
			},
			transactionInfoRes.Transactions[0].Outputs[1].PublicKeyBase58Check)
	}
	{
		transactionInfoRequest := &APITransactionInfoRequest{
			TransactionIDBase58Check: lib.PkToString(txn2.Hash()[:], apiServer.Params),
		}
		jsonRequest, err := json.Marshal(transactionInfoRequest)
		require.NoError(err)
		request, _ := http.NewRequest(
			"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		apiServer.router.ServeHTTP(response, request)
		assert.Equal(200, response.Code, "200 response expected")

		decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
		transactionInfoRes := APITransactionInfoResponse{}
		if err := decoder.Decode(&transactionInfoRes); err != nil {
			require.NoError(err, "Problem decoding response")
		}
		assert.Equal("", transactionInfoRes.Error)
		assert.Equal(1, len(transactionInfoRes.Transactions))
		// Block hash should be empty since this transaction is in the mempool.
		block3Hash, _ := block3.Hash()
		assert.Equal(
			hex.EncodeToString(block3Hash[:]),
			transactionInfoRes.Transactions[0].BlockHashHex)
		assert.Equal(1, len(transactionInfoRes.Transactions[0].Inputs))
		assert.Contains(
			lib.PkToString(txn1.Hash()[:], apiServer.Params),
			transactionInfoRes.Transactions[0].Inputs[0].TransactionIDBase58Check)
		assert.Equal(2, len(transactionInfoRes.Transactions[0].Outputs))
	}

	// Querying for the third block by height should work.
	//{
	//	blockRequest := &APIBlockRequest{
	//		Height:    3,
	//		FullBlock: true,
	//	}
	//	jsonRequest, err := json.Marshal(blockRequest)
	//	require.NoError(err)
	//	request, _ := http.NewRequest(
	//		"POST", RoutePathAPIBlock, bytes.NewBuffer(jsonRequest))
	//	request.Header.Set("Content-Type", "application/json")
	//	response := httptest.NewRecorder()
	//	apiServer.router.ServeHTTP(response, request)
	//	assert.Equal(200, response.Code, "200 response expected")
	//
	//	decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
	//	blockRes := APIBlockResponse{}
	//	if err := decoder.Decode(&blockRes); err != nil {
	//		require.NoError(err, "Problem decoding response")
	//	}
	//	assert.Equal("", blockRes.Error)
	//	assert.Equal(3, len(blockRes.Transactions))
	//	assert.NotNil(blockRes.Header)
	//	assert.Equal(0, int(blockRes.Header.Version))
	//	assert.Equal(block3.Header.Nonce, blockRes.Header.Nonce)
	//	assert.Equal(block3.Header.Height, blockRes.Header.Height)
	//	assert.Equal(hex.EncodeToString(block3.Header.PrevBlockHash[:]), blockRes.Header.PrevBlockHashHex)
	//	assert.Equal(block3.Header.TstampSecs, blockRes.Header.TstampSecs)
	//	assert.Equal(
	//		hex.EncodeToString(block3.Header.TransactionMerkleRoot[:]),
	//		blockRes.Header.TransactionMerkleRootHex)
	//	// Block hash should be empty since this transaction is in the mempool.
	//	block3Hash, _ := block3.Hash()
	//	assert.Equal(
	//		hex.EncodeToString(block3Hash[:]),
	//		blockRes.Transactions[0].BlockHashHex)
	//	assert.Equal(
	//		hex.EncodeToString(block3Hash[:]),
	//		blockRes.Transactions[1].BlockHashHex)
	//	assert.Equal(
	//		hex.EncodeToString(block3Hash[:]),
	//		blockRes.Transactions[2].BlockHashHex)
	//}

	// Querying for the block by hash should work.
	//{
	//	block3Hash, _ := block3.Hash()
	//	blockRequest := &APIBlockRequest{
	//		HashHex:   hex.EncodeToString(block3Hash[:]),
	//		FullBlock: true,
	//	}
	//	jsonRequest, err := json.Marshal(blockRequest)
	//	require.NoError(err)
	//	request, _ := http.NewRequest(
	//		"POST", RoutePathAPIBlock, bytes.NewBuffer(jsonRequest))
	//	request.Header.Set("Content-Type", "application/json")
	//	response := httptest.NewRecorder()
	//	apiServer.router.ServeHTTP(response, request)
	//	assert.Equal(200, response.Code, "200 response expected")
	//
	//	decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
	//	blockRes := APIBlockResponse{}
	//	if err := decoder.Decode(&blockRes); err != nil {
	//		require.NoError(err, "Problem decoding response")
	//	}
	//	assert.Equal("", blockRes.Error)
	//	assert.Equal(3, len(blockRes.Transactions))
	//	assert.NotNil(blockRes.Header)
	//	assert.Equal(0, int(blockRes.Header.Version))
	//	assert.Equal(block3.Header.Nonce, blockRes.Header.Nonce)
	//	assert.Equal(block3.Header.Height, blockRes.Header.Height)
	//	assert.Equal(hex.EncodeToString(block3.Header.PrevBlockHash[:]), blockRes.Header.PrevBlockHashHex)
	//	assert.Equal(block3.Header.TstampSecs, blockRes.Header.TstampSecs)
	//	assert.Equal(
	//		hex.EncodeToString(block3.Header.TransactionMerkleRoot[:]),
	//		blockRes.Header.TransactionMerkleRootHex)
	//	// Block hash should be empty since this transaction is in the mempool.
	//	assert.Equal(
	//		hex.EncodeToString(block3Hash[:]),
	//		blockRes.Transactions[0].BlockHashHex)
	//	assert.Equal(
	//		hex.EncodeToString(block3Hash[:]),
	//		blockRes.Transactions[1].BlockHashHex)
	//	assert.Equal(
	//		hex.EncodeToString(block3Hash[:]),
	//		blockRes.Transactions[2].BlockHashHex)
	//}

	// Set the tip to the first block and make sure all txns get deleted.
	{
		chainWithFirstBlockOnly := apiServer.blockchain.BestChain()[:2]
		oldBestChain := apiServer.blockchain.BestChain()
		apiServer.blockchain.SetBestChain(chainWithFirstBlockOnly)
		require.NoError(apiServer.TXIndex.Update())

		// The miner public key should return one transaction for its single
		// block reward rather than three.
		{
			prefix := lib.DbTxindexTxIDKey(&lib.BlockHash{})[0]
			txnsInTransactionIndex, _ := lib.EnumerateKeysForPrefix(apiServer.TXIndex.TXIndexChain.DB(), []byte{prefix})
			require.Equal(1+len(apiServer.Params.SeedTxns)+len(apiServer.Params.SeedBalances), len(txnsInTransactionIndex))
		}
		{
			keysInPublicKeyTable, _ := lib.EnumerateKeysForPrefix(
				apiServer.TXIndex.TXIndexChain.DB(), lib.DbTxindexPublicKeyPrefix([]byte{}))
			// There should be two keys since one is the miner public key and
			// the other is a dummy public key corresponding to the input of
			// a block reward txn. Plus one for the seed balance, which creates
			// a mapping for the architect pubkey as well as the recipient, and
			// finally for all the seed txns.
			require.Equal(2+ // miner and dummy "from" public key
				len(apiServer.Params.SeedTxns)+ // seed txns each create 1 entry
				(len(apiServer.Params.SeedBalances)+1), /*Seed balance creates two public keys, one is the architect pub key as the "from"*/ len(keysInPublicKeyTable))
		}
		{
			minerPk, _, _ := lib.Base58CheckDecode(senderPkString)
			transactionsInPublicKeyIndex := lib.DbGetTxindexTxnsForPublicKey(
				apiServer.TXIndex.TXIndexChain.DB(), minerPk)
			// The number should be one because there should be a single block
			// reward in the first block and that's it.
			require.Equal(1, len(transactionsInPublicKeyIndex))
		}

		{
			transactionInfoRequest := &APITransactionInfoRequest{
				PublicKeyBase58Check: senderPkString,
			}
			jsonRequest, err := json.Marshal(transactionInfoRequest)
			require.NoError(err)
			request, _ := http.NewRequest(
				"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			apiServer.router.ServeHTTP(response, request)
			assert.Equal(200, response.Code, "200 response expected")

			decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
			transactionInfoRes := APITransactionInfoResponse{}
			if err := decoder.Decode(&transactionInfoRes); err != nil {
				require.NoError(err, "Problem decoding response")
			}
			assert.Equal("", transactionInfoRes.Error)
			assert.Equal(1, len(transactionInfoRes.Transactions))
			assert.Contains(
				[]string{
					hex.EncodeToString(apiServer.blockchain.BestChain()[1].Hash[:]),
				},
				transactionInfoRes.Transactions[0].BlockHashHex)
			assert.Equal(0, len(transactionInfoRes.Transactions[0].Inputs))
			assert.Equal(1, len(transactionInfoRes.Transactions[0].Outputs))
		}
		{
			// Test IDs only
			transactionInfoRequest := &APITransactionInfoRequest{
				PublicKeyBase58Check: senderPkString,
				IDsOnly:              true,
			}
			jsonRequest, err := json.Marshal(transactionInfoRequest)
			require.NoError(err)
			request, _ := http.NewRequest(
				"POST", RoutePathAPITransactionInfo, bytes.NewBuffer(jsonRequest))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			apiServer.router.ServeHTTP(response, request)
			assert.Equal(200, response.Code, "200 response expected")

			decoder := json.NewDecoder(io.LimitReader(response.Body, MaxRequestBodySizeBytes))
			transactionInfoRes := APITransactionInfoResponse{}
			if err := decoder.Decode(&transactionInfoRes); err != nil {
				require.NoError(err, "Problem decoding response")
			}
			assert.Equal("", transactionInfoRes.Error)
			assert.Equal(1, len(transactionInfoRes.Transactions))
			assert.Equal(lib.PkToString(firstBlockTxn.Hash()[:], apiServer.Params),
				transactionInfoRes.Transactions[0].TransactionIDBase58Check)
		}

		// Roll back the change we made to the chain.
		apiServer.blockchain.SetBestChain(oldBestChain)
		require.NoError(apiServer.TXIndex.Update())

		// Now everything should be reset properly.
		{
			prefix := lib.DbTxindexTxIDKey(&lib.BlockHash{})[0]
			txnsInTransactionIndex, _ := lib.EnumerateKeysForPrefix(apiServer.TXIndex.TXIndexChain.DB(), []byte{prefix})
			require.Equal(5+len(apiServer.Params.SeedTxns)+len(apiServer.Params.SeedBalances), len(txnsInTransactionIndex))
		}
		{
			keysInPublicKeyTable, _ := lib.EnumerateKeysForPrefix(
				apiServer.TXIndex.TXIndexChain.DB(), lib.DbTxindexPublicKeyPrefix([]byte{}))
			// Three pairs for the block rewards and two pairs for the transactions
			// we created.
			require.Equal(10+
				len(apiServer.Params.SeedTxns)+ // seed txns each create 1 entry
				(len(apiServer.Params.SeedBalances)+1), /*Seed balance creates two public keys, one is the architect pub key as the "from"*/ len(keysInPublicKeyTable))
		}
	}
}
