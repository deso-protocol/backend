package routes

import (
	"encoding/json"
	"fmt"
	"github.com/deso-protocol/core/lib"
	"github.com/golang/glog"
	"net/http"
	"sort"
	"time"
)

const richListLength = 1000

// Only keep balances in rich list if balance is greater than 100 DESO
const richListMin = 100 * lib.NanosPerUnit

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
				// Get all the balances from the DB
				startPrefix := lib.DbGetPrefixForPublicKeyToDesoBalanceNanos()
				validForPrefix := lib.DbGetPrefixForPublicKeyToDesoBalanceNanos()

				keysFound, valsFound, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
					fes.TXIndex.TXIndexChain.DB(), startPrefix, validForPrefix,
					0, -1, false, true)
				if err != nil {
					glog.Errorf("StartSupplyMonitoring: Error getting all balances")
				}

				var richList []RichListEntry
				// For each key-value pair from the list of all DESO balances, if the balance is high enough to be in
				// the rich list at the current state, add it to our temporary rich list.
				// NOTE: this would be more performance if we kept some sort of priority queue
				for keyIndex, key := range keysFound {
					balanceNanos := lib.DecodeUint64(valsFound[keyIndex])
					totalSupply += balanceNanos
					// We don't need to keep all of the balances, just the top ones so let's skip adding items
					// if we know they won't make the cut.
					if balanceNanos >= richListMin {
						richList = append(richList, RichListEntry{
							KeyBytes:     key,
							BalanceNanos: balanceNanos,
						})
					}
				}

				// Get all the keys for the Prefix that is ordered by DESO locked in creator coins
				uint64BytesLen := 8
				ccStartPrefix := lib.DbPrefixForCreatorDeSoLockedNanosCreatorPKID()
				ccValidForPrefix := lib.DbPrefixForCreatorDeSoLockedNanosCreatorPKID()
				ccKeysFound, _, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
					fes.TXIndex.TXIndexChain.DB(), ccStartPrefix, ccValidForPrefix,
					0, -1, false, false)
				if err != nil {
					glog.Errorf("StartSupplyMonitoring: Error getting all DESO locked in CCs")
				}

				// For each key, extract the DESO locked and add it to the total supply
				for _, ccKey := range ccKeysFound {
					totalSupply += lib.DecodeUint64(ccKey[1 : 1+uint64BytesLen])
				}

				fes.TotalSupplyNanos = totalSupply
				fes.TotalSupplyDESO = float64(totalSupply) / float64(lib.NanosPerUnit)

				sort.Slice(richList, func(ii, jj int) bool {
					return richList[ii].BalanceNanos > richList[jj].BalanceNanos
				})

				richList = richList[:richListLength]

				// Convert RichListEntries to RichListEntryResponses
				var richListResponses []RichListEntryResponse
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
	if !fes.Config.RunSupplyMonitoringRoutine {
		_AddBadRequestError(ww, fmt.Sprintf("Supply Monitoring is not enabled on this node"))
		return
	}
	if err := json.NewEncoder(ww).Encode(fes.TotalSupplyDESO); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetTotalSupply: Error encoding response: %v", err))
		return
	}
}

func (fes *APIServer) GetRichList(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.RunSupplyMonitoringRoutine {
		_AddBadRequestError(ww, fmt.Sprintf("Supply Monitoring is not enabled on this node"))
		return
	}
	if err := json.NewEncoder(ww).Encode(fes.RichList); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetRichList: Error encoding response: %v", err))
		return
	}
}
