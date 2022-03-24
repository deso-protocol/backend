package routes

import (
	"github.com/deso-protocol/core/lib"
	"net/http"
)

type DAOCoinLimitOrder struct {
	Owner    string
	Price    uint64
	Quantity uint64
	Side     string
}

type DAOCoinLimitOrderRequest struct {
	TxnFound bool
}

type DAOCoinLimitOrdersResponse struct {
	LimitOrder []DAOCoinLimitOrder
}

func (fes *APIServer) GetAllDAOCoinLimitOrderForDAO(ww http.ResponseWriter, req *http.Request) {

	_, _ = lib.DBGetAllDAOCoinLimitOrdersForThisDAOCoinPair(
		fes.blockchain.DB(),
		nil,
		nil,
	)

}

type DAOCoinLimitOrderRequestForDAOAndTransactorRequest struct {
	TxnFound bool
}

func (fes *APIServer) GetAllDAOCoinLimitOrdersForTransactor(ww http.ResponseWriter, req *http.Request) {

}
