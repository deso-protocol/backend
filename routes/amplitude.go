package routes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/DataDog/datadog-go/statsd"
	"net/http"
	"time"
)

type AmplitudeUploadRequestBody struct {
	ApiKey string `json:"api_key"`
	Events []AmplitudeEvent `json:"events"`
}

type AmplitudeEvent struct {
	UserId          string `json:"user_id"`
	EventType       string `json:"event_type"`
}

func (fes *APIServer) LogAmplitudeEvent(publicKeyBytes string, event string)  {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept": {"*/*"},

	}
	events := []AmplitudeEvent{{UserId: publicKeyBytes, EventType: event}}
	ampBody := AmplitudeUploadRequestBody{ApiKey: fes.AmplitudeKey, Events: events}
	payload, err := json.Marshal(ampBody)
	if err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetWyreWalletOrderQuotation: Error marshaling JSON body: %v", err))
		return
	}
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest("POST", "https://api2.amplitude.com/2/httpapi", data)
	if err != nil {
		return
	}
	req.Header = headers

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	fmt.Println(resp)
}

func (fes *APIServer) UpdateSeedBalances() {
	go func() {
		out:
			for {
				select {
				case <- time.After(5 * time.Second):
					fes.statsd.Gauge(fmt.Sprintf("STARTER_BITCLOUT_BALANCE"), 1, 1, 1)
				case <- fes.quit
				}
			}
	}
	fes.statsd.Gauge(fmt.Sprintf(""))
	//fes.Getmp.statsd.Gauge(fmt.Sprintf("MEMPOOL.%s.COUNT", k), float64(v.Count), tags, 1)
}
