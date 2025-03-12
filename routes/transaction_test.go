package routes

import (
	"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGetTxns(t *testing.T) {
	apiServer := newTestApiServerWithTxIndex(t)
	var txnHashHex1 string
	var txnHashHex2 string
	{
		// Create a post.
		submitPostReq1 := &SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			BodyObj:                     &lib.DeSoBodySchema{Body: "Hello, world!"},
			MinFeeRateNanosPerKB:        testMinFeeRateNanosPerKB,
		}
		submitPostRes1 := &SubmitPostResponse{}
		makePostRequest(t, apiServer, RoutePathSubmitPost, submitPostReq1, submitPostRes1)
		txnHashHex1 = signAndSubmitTxn(t, apiServer, submitPostRes1.Transaction, senderPrivString)
	}
	{
		// Create a second post.
		submitPostReq2 := &SubmitPostRequest{
			UpdaterPublicKeyBase58Check: senderPkString,
			BodyObj:                     &lib.DeSoBodySchema{Body: "Hello, again!"},
			MinFeeRateNanosPerKB:        testMinFeeRateNanosPerKB,
		}
		submitPostRes2 := &SubmitPostResponse{}
		makePostRequest(t, apiServer, RoutePathSubmitPost, submitPostReq2, submitPostRes2)
		txnHashHex2 = signAndSubmitTxn(t, apiServer, submitPostRes2.Transaction, senderPrivString)
	}
	{
		// Get the first transaction.
		getTxnReq := &GetTxnRequest{
			TxnHashHex: txnHashHex1,
			TxnStatus:  TxnStatusInMempool,
		}
		getTxnRes := &GetTxnResponse{}
		makePostRequest(t, apiServer, RoutePathGetTxn, getTxnReq, getTxnRes)
		require.True(t, getTxnRes.TxnFound)
	}
	{
		// Get both transactions.
		getTxnsReq := &GetTxnsRequest{
			TxnHashHexes: []string{txnHashHex1, txnHashHex2},
			TxnStatus:    TxnStatusInMempool,
		}
		getTxnsRes := &GetTxnsResponse{}
		makePostRequest(t, apiServer, RoutePathGetTxns, getTxnsReq, getTxnsRes)
		require.True(t, getTxnsRes.TxnsFound[txnHashHex1])
		require.True(t, getTxnsRes.TxnsFound[txnHashHex2])
	}
}
