package model

type Notification struct {
	TransactionHash *string  `json:"transactionHash"`
	FromPublicKey   *string  `json:"from"`
	OtherPublicKey  *string  `json:"other"`
	Type            *int     `json:"type"`
	Amount          *float64 `json:"amount"`
	PostHash        *string  `json:"postHash"`
	Timestamp       *int     `json:"timestamp"`
}
