package apis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang/glog"
	"github.com/montanaflynn/stats"
	"io/ioutil"
	"net/http"
	"strconv"
)

type CoinbaseResponse struct {
	Data struct {
		Amount string `json:"amount"`
	} `json:"data"`
}

type CoingeckoResponse struct {
	Bitcoin struct {
		USD float64 `json:"usd"`
	} `json:"ethereum"`
}

type BlockchainDotcomResponse struct {
	LastTradePrice float64 `json:"last_trade_price"`
}

type GeminiResponse struct {
	Last string `json:"last"`
}

type KrakenResponse struct {
	Result struct {
		Ticker struct {
			LastPriceList []string `json:"c"`
		} `json:"XETHZUSD"`
	} `json:"result"`
}

func getCoinbasePrice() (float64, error) {
	URL := "https://api.coinbase.com/v2/prices/ETH-USD/buy"
	req, _ := http.NewRequest("GET", URL, nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Error getting price: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Error getting price: Status code: %v: %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	responseData := &CoinbaseResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return 0, fmt.Errorf("Error decoding response: %v, response: %v, error: %v", responseData, resp, err)
	}

	amount, err := strconv.ParseFloat(responseData.Data.Amount, 64)
	if err != nil {
		return 0, fmt.Errorf("Error parsing amount into float: %v", err)
	}

	return amount, nil
}

func getCoingeckoPrice() (float64, error) {
	URL := "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
	req, _ := http.NewRequest("GET", URL, nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Error getting price: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Error getting price: Status code: %v: %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	responseData := &CoingeckoResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return 0, fmt.Errorf("Error decoding response %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData.Bitcoin.USD, nil
}

func getBlockchainDotcomPrice() (float64, error) {
	URL := "https://api.blockchain.com/v3/exchange/tickers/ETH-USD"
	req, _ := http.NewRequest("GET", URL, nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Error getting price: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Error getting price: Status code: %v: %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	responseData := &BlockchainDotcomResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return 0, fmt.Errorf("Error decoding response %v, response: %v, error: %v", responseData, resp, err)
	}

	return responseData.LastTradePrice, nil
}

func getGeminiPrice() (float64, error) {
	URL := "https://api.gemini.com/v1/pubticker/ethusd"
	req, _ := http.NewRequest("GET", URL, nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Error getting price: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Error getting price: Status code: %v: %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	responseData := &GeminiResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return 0, fmt.Errorf("Error decoding response %v, response: %v, error: %v", responseData, resp, err)
	}

	amount, err := strconv.ParseFloat(responseData.Last, 64)
	if err != nil {
		return 0, fmt.Errorf("Error parsing amount into float: %v", err)
	}

	return amount, nil
}

func getKrakenPrice() (float64, error) {
	URL := "https://api.kraken.com/0/public/Ticker?pair=XETHZUSD"
	req, _ := http.NewRequest("GET", URL, nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Error getting price: %v", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Error getting price: Status code: %v: %v", resp.StatusCode, string(body))
	}

	// Decode the response into the appropriate struct.
	responseData := &KrakenResponse{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(responseData); err != nil {
		return 0, fmt.Errorf("Error decoding response %v, response: %v, error: %v", responseData, resp, err)
	}

	if len(responseData.Result.Ticker.LastPriceList) == 0 {
		return 0, fmt.Errorf("Error: Last price list had no entries")
	}

	amount, err := strconv.ParseFloat(responseData.Result.Ticker.LastPriceList[0], 64)
	if err != nil {
		return 0, fmt.Errorf("Error parsing amount into float: %v", err)
	}

	return amount, nil
}

func GetUSDToETHPrice() (float64, error) {
	amounts := []float64{}
	{
		amount, err := getCoinbasePrice()
		if err != nil {
			// The amount will be zero in this case, which is fine
			glog.Errorf("Error fetching Coinbase price: %v", err)
		}

		if amount != 0 {
			amounts = append(amounts, amount)
		}
	}
	{
		amount, err := getCoingeckoPrice()
		if err != nil {
			// The amount will be zero in this case, which is fine
			glog.Errorf("Error fetching Coingecko price: %v", err)
		}

		if amount != 0 {
			amounts = append(amounts, amount)
		}
	}
	{
		amount, err := getBlockchainDotcomPrice()
		if err != nil {
			// The amount will be zero in this case, which is fine
			glog.Errorf("Error fetching blockchain.com price: %v", err)
		}

		if amount != 0 {
			amounts = append(amounts, amount)
		}
	}
	{
		amount, err := getGeminiPrice()
		if err != nil {
			// The amount will be zero in this case, which is fine
			glog.Errorf("Error fetching Gemini price: %v", err)
		}

		if amount != 0 {
			amounts = append(amounts, amount)
		}
	}
	{
		amount, err := getKrakenPrice()
		if err != nil {
			// The amount will be zero in this case, which is fine
			glog.Errorf("Error fetching Kraken price: %v", err)
		}

		if amount != 0 {
			amounts = append(amounts, amount)
		}
	}

	if len(amounts) == 0 {
		return 0, fmt.Errorf("Didn't find any prices from API's")
	}

	finalETHUSDPrice, err := stats.Median(amounts)
	if err != nil {
		return 0, fmt.Errorf("Error computing the median")
	}
	return finalETHUSDPrice, nil
}
