package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"math"
	"net/http"
	"sort"
	"time"
)

const richListLength = 1000

type RichListEntry struct {
	KeyBytes     []byte
	BalanceNanos uint64
}

type RichListEntryResponse struct {
	PublicKeyBase58Check string
	BalanceNanos         uint64
	BalanceDESO          float64
	Percentage           float64
	Value                float64
}

// StartSupplyMonitoring begins monitoring the top 1000 public keys with the most DESO and the total supply
func (fes *APIServer) StartSupplyMonitoring() {
	go func() {
	out:
		for {
			select {
			case <-time.After(10 * time.Minute):
				totalSupply := uint64(0)
				lowestValOnRichlist := uint64(math.MaxUint64)
				startPrefix := lib.DbGetPrefixForPublicKeyToDesoBalanceNanos()
				validForPrefix := lib.DbGetPrefixForPublicKeyToDesoBalanceNanos()

				keysFound, valsFound, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
					fes.TXIndex.TXIndexChain.DB(), startPrefix, validForPrefix,
					0, -1, false, true)
				if err != nil {
					glog.Errorf("StartSupplyMonitoring: Error getting all balances")
				}
				var richList []RichListEntry
				for keyIndex, key := range keysFound {
					balanceNanos := lib.DecodeUint64(valsFound[keyIndex])
					totalSupply += balanceNanos
					if len(richList) < richListLength || balanceNanos > lowestValOnRichlist {
						if balanceNanos < lowestValOnRichlist {
							lowestValOnRichlist = balanceNanos
						}
						richList = append(richList, RichListEntry{
							KeyBytes:     key,
							BalanceNanos: balanceNanos,
						})
					}
				}
				if fes.TotalSupplyNanos < totalSupply {
					fes.TotalSupplyNanos = totalSupply
					fes.TotalSupplyDESO = float64(totalSupply) / float64(lib.NanosPerUnit)
				}
				sort.Slice(richList, func(ii, jj int) bool {
					return richList[ii].BalanceNanos > richList[jj].BalanceNanos
				})

				var richListResponses []RichListEntryResponse
				richList = richList[:richListLength]
				for _, item := range richList {
					richListResponses = append(richListResponses, RichListEntryResponse{
						PublicKeyBase58Check: lib.PkToString(item.KeyBytes[1:], fes.Params),
						BalanceNanos:         item.BalanceNanos,
						BalanceDESO:          float64(item.BalanceNanos) / float64(lib.NanosPerUnit),
						Value:                fes.GetUSDFromNanos(item.BalanceNanos),
						Percentage:           float64(item.BalanceNanos) / float64(totalSupply),
					})
				}
				fes.RichList = richListResponses
			case <-fes.quit:
				break out
			}
		}
	}()
}

func (fes *APIServer) GetTotalSupply(ww http.ResponseWriter, req *http.Request) {
	if err := json.NewEncoder(ww).Encode(fes.TotalSupplyDESO); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTotalSupply: Error encoding response: %v", err))
		return
	}
}

func (fes *APIServer) GetRichList(ww http.ResponseWriter, req *http.Request) {
	if err := json.NewEncoder(ww).Encode(fes.RichList); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRichList: Error encoding response: %v", err))
		return
	}
}
