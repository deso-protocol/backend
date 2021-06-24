package globaldb

import "github.com/bitclout/core/lib"

type WyreOrder struct {
	WyreOrderId     string `pg:",pk"`
	PublicKey       *lib.PublicKey
	LastPayload     *WyreWalletOrderWebhookPayload
	LastWalletOrder *WyreTrackOrderResponse
	BitCloutNanos   uint64 `pg:",use_zero"`
	TransferTxnHash *lib.BlockHash
	Processed       bool `pg:",use_zero"`
}

type WyreWalletOrderWebhookPayload struct {
	// referenceId holds the public key of the user who made initiated the wallet order
	ReferenceId  string `json:"referenceId"`
	AccountId    string `json:"accountId"`
	OrderId      string `json:"orderId"`
	OrderStatus  string `json:"orderStatus"`
	TransferId   string `json:"transferId"`
	FailedReason string `json:"failedReason"`
}

type WyreTrackOrderResponse struct {
	TransferId  string  `json:"transferId"`
	FeeCurrency string  `json:"feeCurrency"`
	Fee         float64 `json:"fee"`
	Fees        struct {
		BTC float64 `json:"BTC"`
		USD float64 `json:"USD"`
	} `json:"fees"`
	SourceCurrency           string      `json:"sourceCurrency"`
	DestCurrency             string      `json:"destCurrency"`
	SourceAmount             float64     `json:"sourceAmount"`
	DestAmount               float64     `json:"destAmount"`
	DestSrn                  string      `json:"destSrn"`
	From                     string      `json:"from"`
	To                       interface{} `json:"to"`
	Rate                     float64     `json:"rate"`
	CustomId                 interface{} `json:"customId"`
	Status                   interface{} `json:"status"`
	BlockchainNetworkTx      interface{} `json:"blockchainNetworkTx"`
	Message                  interface{} `json:"message"`
	TransferHistoryEntryType string      `json:"transferHistoryEntryType"`
	SuccessTimeline          []struct {
		StatusDetails string `json:"statusDetails"`
		State         string `json:"state"`
		CreatedAt     int64  `json:"createdAt"`
	} `json:"successTimeline"`
	FailedTimeline []interface{} `json:"failedTimeline"`
	FailureReason  interface{}   `json:"failureReason"`
	ReversalReason interface{}   `json:"reversalReason"`
}

func (global *GlobalDB) GetWyreOrder(wyreOrderId string) *WyreOrder {
	var wyreOrder *WyreOrder
	err := global.db.Model(wyreOrder).Where("wyre_order_id = ?", wyreOrderId).Select()
	if err != nil {
		return nil
	}
	return wyreOrder
}

func (global *GlobalDB) GetWyreOrders(publicKey *lib.PublicKey) []*WyreOrder {
	var wyreOrders []*WyreOrder
	err := global.db.Model(&wyreOrders).Where("public_key = ?", publicKey).Select()
	if err != nil {
		return nil
	}
	return wyreOrders
}

func (global *GlobalDB) SaveWyreOrder(wyreOrder *WyreOrder) {
	_, _ = global.db.Model(wyreOrder).WherePK().Update()
}
