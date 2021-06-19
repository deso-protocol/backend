package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bitclout/core/lib"
	"github.com/golang/glog"
	"github.com/montanaflynn/stats"
	"io"
	"io/ioutil"
	"net/http"
)

// Index ...
func (fes *APIServer) Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Your BitClout node is running!\n")
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
	SatoshisPerBitCloutExchangeRate        uint64
	NanosSold                              uint64
	USDCentsPerBitcoinExchangeRate         uint64
	USDCentsPerBitCloutExchangeRate        uint64
	USDCentsPerBitCloutReserveExchangeRate uint64
	BuyBitCloutFeeBasisPoints              uint64
}

func (fes *APIServer) GetExchangeRate(ww http.ResponseWriter, rr *http.Request) {
	// Get the Bitcoin to USD exchange rate by applying txns in the mempool.
	readUtxoView, _ := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	usdCentsPerBitcoin := readUtxoView.GetCurrentUSDCentsPerBitcoin()

	startNanos := readUtxoView.NanosPurchased

	var satoshisPerUnit uint64
	nanosPerSat, err := fes.GetNanosFromSats(1, 0)
	if err != nil {
		glog.Errorf("GetExchangeRate: error getting BitCloutNanos per BitCoin: %v", err)
		satoshisPerUnit =  lib.GetSatoshisPerUnitExchangeRate(startNanos, usdCentsPerBitcoin)
	} else {
		satoshisPerUnit = lib.NanosPerUnit / nanosPerSat
	}

	usdCentsPerBitCloutExchangeRate := fes.GetExchangeBitCloutPrice()

	usdCentsPerBitCloutReserveExchangeRate, err := fes.GetUSDCentsToBitCloutReserveExchangeRateFromGlobalState()
	if err != nil {
		glog.Errorf("GetExchangeRate: error getting reserve exchange rate from global state: %v", err)
		usdCentsPerBitCloutReserveExchangeRate = 0
	}

	feeBasisPoints, err := fes.GetBuyBitCloutFeeBasisPointsResponseFromGlobalState()
	if err != nil {
		glog.Errorf("GetExchangeRate: error getting buy bitclout fee basis points from global state: %v", err)
		feeBasisPoints = 0
	}

	res := &GetExchangeRateResponse{
		SatoshisPerBitCloutExchangeRate: satoshisPerUnit,
		NanosSold:                       startNanos,
		USDCentsPerBitcoinExchangeRate:  usdCentsPerBitcoin,
		USDCentsPerBitCloutExchangeRate: usdCentsPerBitCloutExchangeRate,
		USDCentsPerBitCloutReserveExchangeRate: usdCentsPerBitCloutReserveExchangeRate,
		BuyBitCloutFeeBasisPoints: feeBasisPoints,
	}

	if err = json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetExchangeRate: Problem encoding response as JSON: %v", err))
		return
	}
}

func (fes *APIServer) GetExchangeBitCloutPrice() uint64 {
	blockchainPrice := fes.UsdCentsPerBitCloutExchangeRate
	reservePrice, err := fes.GetUSDCentsToBitCloutReserveExchangeRateFromGlobalState()
	if err != nil {
		glog.Errorf("Getting reserve price from global state failed. Only using ticker price: %v", err)
		reservePrice = 0
	}
	if blockchainPrice > reservePrice {
		return blockchainPrice
	}
	return reservePrice
}

type BlockchainBitCloutTickerResponse struct {
	Symbol string `json:"symbol"`
	Price24H float64 `json:"price_24h"`
	Volume24H float64 `json:"volume_24h"`
	LastTradePrice float64 `json:"last_trade_price"`
}

// UpdateUSDCentsToBitCloutExchangeRate updates app state's USD Cents per BitClout value
func (fes *APIServer) UpdateUSDCentsToBitCloutExchangeRate() {
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
		responseData := &BlockchainBitCloutTickerResponse{}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err = decoder.Decode(responseData); err != nil {
			glog.Errorf("GetExchangePriceFromBlockchain: Problem decoding response JSON into "+
				"interface %v, response: %v, error: %v", responseData, resp, err)
			return
		}

		// Return the last trade price.
		usdCentsToBitCloutExchangePrice := uint64(responseData.LastTradePrice * 100)

		exchangeRatesFetched = append(exchangeRatesFetched, float64(usdCentsToBitCloutExchangePrice))
	}
	blockchainDotComExchangeRate, err := stats.Max(exchangeRatesFetched)
	if err != nil {
		glog.Error(err)
	}
	glog.Infof("Blockchain exchange rate: %v %v", blockchainDotComExchangeRate, exchangeRatesFetched)

	// Get the reserve price for this node.
	reservePrice, err := fes.GetUSDCentsToBitCloutReserveExchangeRateFromGlobalState()
	// If the max of last trade price and 24H price is less than the reserve price, use the reserve price.
	if reservePrice > uint64(blockchainDotComExchangeRate) {
		fes.UsdCentsPerBitCloutExchangeRate = reservePrice
	} else {
		fes.UsdCentsPerBitCloutExchangeRate = uint64(blockchainDotComExchangeRate)
	}

	glog.Infof("Final exchange rate: %v", fes.UsdCentsPerBitCloutExchangeRate)
}

type GetAppStateRequest struct {
	PublicKeyBase58Check string
}

type GetAppStateResponse struct {
	AmplitudeKey                        string
	AmplitudeDomain                     string
	MinSatoshisBurnedForProfileCreation uint64
	IsTestnet                           bool
	SupportEmail                        string
	ShowProcessingSpinners              bool

	HasStarterBitCloutSeed bool
	HasTwilioAPIKey        bool
	CreateProfileFeeNanos  uint64
	CompProfileCreation    bool
	DiamondLevelMap        map[int64]uint64
	HasWyreIntegration     bool

	// Send back the password stored in our HTTPOnly cookie
	// so amplitude can track which passwords people are using
	Password string
}

func (fes *APIServer) GetAppState(ww http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(io.LimitReader(req.Body, MaxRequestBodySizeBytes))
	requestData := GetAppStateRequest{}
	if err := decoder.Decode(&requestData); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf(
			"GetAppState: Problem parsing request body: %v", err))
		return
	}

	hasTwilioAPIKey := false
	if fes.Twilio != nil {
		hasTwilioAPIKey = true
	}

	hasStarterBitCloutSeed := false
	if fes.StarterBitCloutSeed != "" {
		hasStarterBitCloutSeed = true
	}

	// Get a view with all the mempool transactions (used to get all posts / reader state).
	utxoView, err := fes.backendServer.GetMempool().GetAugmentedUniversalView()
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetAppState: Error getting augmented universal view: %v", err))
		return
	}

	res := &GetAppStateResponse{
		AmplitudeKey:                        fes.AmplitudeKey,
		AmplitudeDomain:                     fes.AmplitudeDomain,
		ShowProcessingSpinners:              fes.ShowProcessingSpinners,
		MinSatoshisBurnedForProfileCreation: fes.MinSatoshisBurnedForProfileCreation,
		IsTestnet:                           fes.Params.NetworkType == lib.NetworkType_TESTNET,
		SupportEmail:                        fes.SupportEmail,
		HasTwilioAPIKey:                     hasTwilioAPIKey,
		HasStarterBitCloutSeed:              hasStarterBitCloutSeed,
		CreateProfileFeeNanos:               utxoView.GlobalParamsEntry.CreateProfileFeeNanos,
		CompProfileCreation:                 fes.IsCompProfileCreation,
		DiamondLevelMap:                     lib.GetBitCloutNanosDiamondLevelMapAtBlockHeight(int64(fes.blockchain.BlockTip().Height)),
		HasWyreIntegration:                  fes.IsConfiguredForWyre(),
	}

	if err := json.NewEncoder(ww).Encode(res); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetNotifications: Problem encoding response as JSON: %v", err))
		return
	}
}
