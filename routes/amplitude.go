package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type AmplitudeUploadRequestBody struct {
	ApiKey string `json:"api_key"`
	Events []AmplitudeEvent `json:"events"`
}

type AmplitudeEvent struct {
	UserId          string `json:"user_id"`
	EventType       string `json:"event_type"`
	EventProperties map[string]interface{} `json:"event_properties"`
}

func (fes *APIServer) LogAmplitudeEvent(publicKeyBytes string, event string, eventData map[string]interface{})  error {
	if fes.AmplitudeKey == "" {
		return nil
	}
	headers := map[string][]string{
		"Content-Type": {"application/json"},
		"Accept":       {"*/*"},
	}
	events := []AmplitudeEvent{{UserId: publicKeyBytes, EventType: event, EventProperties: eventData}}
	ampBody := AmplitudeUploadRequestBody{ApiKey: fes.AmplitudeKey, Events: events}
	payload, err := json.Marshal(ampBody)
	if err != nil {
		return err
	}
	data := bytes.NewBuffer(payload)
	req, err := http.NewRequest("POST", "https://api2.amplitude.com/2/httpapi", data)
	if err != nil {
		return err
	}
	req.Header = headers

	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		return err
	}
	return nil
}
