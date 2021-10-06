package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/backend/apis"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"github.com/montanaflynn/stats"
)

// Index ...
func (fes *APIServer) Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Your DeSo node is running!\n")
}

// NOTE: This is a readiness check not a health check
func (fes *APIServer) HealthCheck(ww http.ResponseWriter, rr *http.Request) {
	// Check that the blockchain is fully current.
	blockchainHeight := fes.blockchain.BlockTip().Height
	if fes.blockchain.ChainState() != lib.SyncStateFullyCurrent {
		_AddBadRequestError(ww, fmt.Sprintf("Waiting for blockchain to sync. "+
			"Height: %v, SyncState: %v", blockchainHeight, fes.blockchain.ChainState()))
		return
	}

	// Check that we've received our first transaction bundle.
	if !fes.backendServer.HasProcessedFirstTransactionBundle() {
		_AddBadRequestError(ww, "Waiting on mempool to sync")
		return
	}

	fmt.Fprint(ww, "200")
}

type GetExchangeRateResponse struct {
	// BTC
	SatoshisPerDeSoExchangeRate    uint64
	USDCentsPerBitcoinExchangeRate uint64

	// ETH
	NanosPerETHExchangeRate    uint64
	USDCentsPerETHExchangeRate uint64

	// DESO
	NanosSold                          uint64
	USDCentsPerDeSoExchangeRate        uint64
	USDCentsPerDeSoReserveExchangeRate uint64
	BuyDeSoFeeBasisPoints              uint64

	SatoshisPerBitCloutExchangeRate        uint64 // Deprecated
	USDCentsPerBitCloutExchangeRate        uint64 // Deprecated
	USDCentsPerBitCloutReserveExchangeRate uint64 // Deprecated
}

func (fes *APIServer) GetExchangeRate(ww http.ResponseWriter, rr *http.Request) {
	readUtxoView, _ := fes.backendServer.GetMempool().GetAugmentedUniversalView()

	// BTC
	usdCentsPerBitcoin := fes.UsdCentsPerBitCoinExchangeRate
	// If we don't have a valid value from monitoring at this time, use the price from the protocol
	if usdCentsPerBitcoin == 0 {
		usdCentsPerBitcoin = float64(readUtxoView.GetCurrentUSDCentsPerBitcoin())
	}

	// ETH
	usdCentsPerETH := fes.UsdCentsPerETHExchangeRate
	nanosPerETH := fes.GetNanosFromETH(big.NewFloat(1), 0)

	usdCentsPerDeSoExchangeRate := fes.GetExchangeDeSoPrice()
	satoshisPerUnit := lib.NanosPerUnit / fes.GetNanosFromSats(1, 0)

	// DESO
	usdCentsPerDeSoReserveExchangeRate, err := fes.GetUSDCentsToDeSoReserveExchangeRateFromGlobalState()

	if err != nil {
		glog.Errorf("GetExchangeRate: error getting reserve exchange rate from global state: %v", err)
		usdCentsPerDeSoReserveExchangeRate = 0
	}

	startNanos := readUtxoView.NanosPurchased
	feeBasisPoints, err := fes.GetBuyDeSoFeeBasisPointsResponseFromGlobalState()

	if err != nil {
		glog.Errorf("GetExchangeRate: error getting buy deso fee basis points from global state: %v", err)
		feeBasisPoints = 0
	}

	res := &GetExchangeRateResponse{
		// BTC
		USDCentsPerBitcoinExchangeRate: uint64(usdCentsPerBitcoin),
		SatoshisPerDeSoExchangeRate:    satoshisPerUnit,

		// ETH
		USDCentsPerETHExchangeRate: usdCentsPerETH,
		NanosPerETHExchangeRate:    nanosPerETH,

		// DESO
		NanosSold:                          startNanos,
		USDCentsPerDeSoExchangeRate:        usdCentsPerDeSoExchangeRate,
		USDCentsPerDeSoReserveExchangeRate: usdCentsPerDeSoReserveExchangeRate,
		BuyDeSoFeeBasisPoints:              feeBasisPoints,

		// Deprecated
		SatoshisPerBitCloutExchangeRate:        satoshisPerUnit,
		USDCentsPerBitCloutExchangeRate:        usdCentsPerDeSoExchangeRate,
		USDCentsPerBitCloutReserveExchangeRate: usdCentsPerDeSoReserveExchangeRate,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetExchangeDeSoPrice() uint64 {
	blockchainPrice := fes.UsdCentsPerDeSoExchangeRate
	reservePrice, err := fes.GetUSDCentsToDeSoReserveExchangeRateFromGlobalState()
	if err != nil {
		glog.Errorf("Getting reserve price from global state failed. Only using ticker price: %v", err)
		reservePrice = 0
	}
	if blockchainPrice > reservePrice {
		return blockchainPrice
	}
	return reservePrice
}

type BlockchainDeSoTickerResponse struct {
	Symbol         string  `json:"symbol"`
	Price24H       float64 `json:"price_24h"`
	Volume24H      float64 `json:"volume_24h"`
	LastTradePrice float64 `json:"last_trade_price"`
}

// UpdateUSDCentsToDeSoExchangeRate updates app state's USD Cents per DeSo value
func (fes *APIServer) UpdateUSDCentsToDeSoExchangeRate() {
	glog.Infof("Refreshing exchange rate...")

	// Get the ticker from Blockchain.com
	// Do several fetches and take the max
	//
	// TODO: This is due to a bug in Blockchain's API that returns random values ~30% of the
	// time for the last_price field. Once that bug is fixed, this multi-fetching will no
	// longer be needed.
	exchangeRatesFetched := []float64{}
	for ii := 0; ii < 10; ii++ {
		url := "https://api.blockchain.com/v3/exchange/tickers/CLOUT-USD"
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			glog.Errorf("GetExchangePriceFromBlockchain: Problem with HTTP request %s: %v", url, err)
			return
		}
		defer resp.Body.Close()

		// Decode the response into the appropriate struct.
		body, _ := ioutil.ReadAll(resp.Body)
		responseData := &BlockchainDeSoTickerResponse{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err = decoder.Decode(responseData); err != nil {
			glog.Errorf("GetExchangePriceFromBlockchain: Problem decoding response JSON into "+
				"interface %v, response: %v, error: %v", responseData, resp, err)
			return
		}

		// Return the last trade price.
		usdCentsToDeSoExchangePrice := uint64(responseData.LastTradePrice * 100)

		exchangeRatesFetched = append(exchangeRatesFetched, float64(usdCentsToDeSoExchangePrice))
	}
	blockchainDotComExchangeRate, err := stats.Max(exchangeRatesFetched)
	if err != nil {
		glog.Error(err)
	}
	glog.Infof("Blockchain exchange rate: %v %v", blockchainDotComExchangeRate, exchangeRatesFetched)
	if fes.backendServer != nil && fes.backendServer.GetStatsdClient() != nil {
		if err = fes.backendServer.GetStatsdClient().Gauge("BLOCKCHAIN_LAST_TRADE_PRICE", blockchainDotComExchangeRate, []string{}, 1); err != nil {
			glog.Errorf("GetExchangePriceFromBlockchain: Error logging Last Trade Price of %f to datadog: %v", blockchainDotComExchangeRate, err)
		}
	}

	// Get the current timestamp and append the current last trade price to the LastTradeDeSoPriceHistory slice
	timestamp := uint64(time.Now().UnixNano())
	fes.LastTradeDeSoPriceHistory = append(fes.LastTradeDeSoPriceHistory, LastTradePriceHistoryItem{
		LastTradePrice: uint64(blockchainDotComExchangeRate),
		Timestamp:      timestamp,
	})

	// Get the max price within the lookback window and remove elements that are no longer valid.
	maxPrice := fes.getMaxPriceFromHistoryAndCull(timestamp)

	// Get the reserve price for this node.
	reservePrice, err := fes.GetUSDCentsToDeSoReserveExchangeRateFromGlobalState()
	// If the max of last trade price and 24H price is less than the reserve price, use the reserve price.
	if reservePrice > maxPrice {
		fes.UsdCentsPerDeSoExchangeRate = reservePrice
	} else {
		fes.UsdCentsPerDeSoExchangeRate = maxPrice
	}

	glog.Infof("Final exchange rate: %v", fes.UsdCentsPerDeSoExchangeRate)
}

func (fes *APIServer) UpdateUSDToBTCPrice() {
	glog.Info("Refreshing USD to BTC exchange rate")
	btcExchangeRate, err := GetUSDToBTCPrice()
	if err != nil {
		glog.Errorf("Error getting BTC price: %v", err)
		return
	}
	fes.UsdCentsPerBitCoinExchangeRate = btcExchangeRate * 100
	glog.Infof("New USD to BTC exchange rate: %f", fes.UsdCentsPerBitCoinExchangeRate/100)
}

func (fes *APIServer) UpdateUSDToETHPrice() {
	glog.Info("Refreshing USD to ETH exchange rate")
	ethExchangeRate, err := apis.GetUSDToETHPrice()
	if err != nil {
		glog.Errorf("Error getting ETH price: %v", err)
		return
	}
	fes.UsdCentsPerETHExchangeRate = uint64(ethExchangeRate * 100)
	glog.Infof("New USD to ETH exchange rate: %f", float64(fes.UsdCentsPerETHExchangeRate)/100)
}

// getMaxPriceFromHistoryAndCull removes elements that are outside of the lookback window and return the max price
// from valid elements.
func (fes *APIServer) getMaxPriceFromHistoryAndCull(currentTimestamp uint64) uint64 {
	maxPrice := uint64(0)
	// This function culls invalid values (outside of the lookback window) from the LastTradeDeSoPriceHistory slice
	// in place, so we need to keep track of the index at which we will place the next valid item.
	validIndex := 0
	for _, priceHistoryItem := range fes.LastTradeDeSoPriceHistory {
		tstampDiff := currentTimestamp - priceHistoryItem.Timestamp
		if tstampDiff <= fes.LastTradePriceLookback {
			// copy and increment index.  This overwrites invalid values with valid ones in the order valid items
			// are seen.
			fes.LastTradeDeSoPriceHistory[validIndex] = priceHistoryItem
			validIndex++
			if priceHistoryItem.LastTradePrice > maxPrice {
				maxPrice = priceHistoryItem.LastTradePrice
			}
		}
	}
	// Reduce the slice to only valid elements - all elements up to validIndex are within the lookback window.
	fes.LastTradeDeSoPriceHistory = fes.LastTradeDeSoPriceHistory[:validIndex]
	return maxPrice
}

type GetAppStateRequest struct {
	PublicKeyBase58Check string
}

type GetAppStateResponse struct {
	AmplitudeKey                        string
	AmplitudeDomain                     string
	MinSatoshisBurnedForProfileCreation uint64
	BlockHeight                         uint32
	IsTestnet                           bool
	SupportEmail                        string
	ShowProcessingSpinners              bool

	HasStarterDeSoSeed    bool
	HasTwilioAPIKey       bool
	CreateProfileFeeNanos uint64
	CompProfileCreation   bool
	DiamondLevelMap       map[int64]uint64
	HasWyreIntegration    bool
	HasJumioIntegration   bool
	BuyWithETH            bool

	USDCentsPerDeSoExchangeRate uint64
	JumioDeSoNanos              uint64

	USDCentsPerBitCloutExchangeRate uint64 // Deprecated
	JumioBitCloutNanos              uint64 // Deprecated
}

func (fes *APIServer) GetAppState(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAppStateRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetAppState: Problem parsing request body: %v", err))
		return
	}

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAppState: Error getting augmented universal view: %v", err))
		return
	}

	res := &GetAppStateResponse{
		AmplitudeKey:                        fes.Config.AmplitudeKey,
		AmplitudeDomain:                     fes.Config.AmplitudeDomain,
		ShowProcessingSpinners:              fes.Config.ShowProcessingSpinners,
		MinSatoshisBurnedForProfileCreation: fes.Config.MinSatoshisForProfile,
		BlockHeight:                         fes.backendServer.GetBlockchain().BlockTip().Height,
		IsTestnet:                           fes.Params.NetworkType == lib.NetworkType_TESTNET,
		SupportEmail:                        fes.Config.SupportEmail,
		HasTwilioAPIKey:                     fes.Twilio != nil,
		HasStarterDeSoSeed:                  fes.Config.StarterDeSoSeed != "",
		CreateProfileFeeNanos:               utxoView.GlobalParamsEntry.CreateProfileFeeNanos,
		CompProfileCreation:                 fes.Config.CompProfileCreation,
		DiamondLevelMap:                     lib.GetDeSoNanosDiamondLevelMapAtBlockHeight(int64(fes.blockchain.BlockTip().Height)),
		HasWyreIntegration:                  fes.IsConfiguredForWyre(),
		HasJumioIntegration:                 fes.IsConfiguredForJumio(),
		BuyWithETH:                          fes.IsConfiguredForETH(),
		USDCentsPerDeSoExchangeRate:         fes.GetExchangeDeSoPrice(),
		JumioDeSoNanos:                      fes.GetJumioDeSoNanos(),

		// Deprecated
		USDCentsPerBitCloutExchangeRate: fes.GetExchangeDeSoPrice(),
		JumioBitCloutNanos:              fes.GetJumioDeSoNanos(),
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNotifications: Problem encoding response as JSON: %v", err))
		return
	}
}
