package routes

import (
	"bytes"
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
				fes.UpdateSupplyStats()
			case <-fes.quit:
				break out
			}
		}
	}()
}

func (fes *APIServer) UpdateSupplyStats() {
	// Prevent access to the DB while it's reset. This only happens when we're syncing a snapshot.
	if fes.backendServer.GetBlockchain().ChainState() == lib.SyncStateSyncingSnapshot {
		fes.backendServer.DbMutex.Lock()
		defer fes.backendServer.DbMutex.Unlock()
	}
	totalSupply := uint64(0)
	totalKeysWithDESO := uint64(0)
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
		if balanceNanos > 0 {
			totalKeysWithDESO++
		}
		// We don't need to keep all of the balances, just the top ones so let's skip adding items
		// if we know they won't make the cut.
		if balanceNanos >= richListMin {
			richList = append(richList, RichListEntry{
				KeyBytes:     key,
				BalanceNanos: balanceNanos,
			})
		}
	}

	fes.CountKeysWithDESO = totalKeysWithDESO

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

	validatorsStartPrefix := append([]byte{}, lib.Prefixes.PrefixValidatorByStatusAndStakeAmount...)
	validatorsValidForPrefix := append([]byte{}, lib.Prefixes.PrefixValidatorByStatusAndStakeAmount...)
	validatorsKeysFound, _, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
		fes.TXIndex.TXIndexChain.DB(), validatorsStartPrefix, validatorsValidForPrefix,
		0, -1, false, false)
	if err != nil {
		glog.Errorf("StartSupplyMonitoring: Error getting all validators")
	}
	totalStakeSupply := uint64(0)
	for _, validatorKey := range validatorsKeysFound {
		validatorStakeAmount, err := lib.FixedWidthDecodeUint256(bytes.NewReader(validatorKey[2:]))
		if err != nil {
			glog.Errorf("StartSupplyMonitoring: Error decoding validator stake amount: %v", err)
			continue
		}
		if validatorStakeAmount == nil || !validatorStakeAmount.IsUint64() {
			glog.Errorf("StartSupplyMonitoring: Validator stake amount is not a uint64")
			continue
		}
		totalStakeSupply += validatorStakeAmount.Uint64()
	}
	totalSupply += totalStakeSupply

	lockedStakeStartPrefix := append([]byte{}, lib.Prefixes.PrefixLockedStakeByValidatorAndStakerAndLockedAt...)
	lockedStakeValidForPrefix := append([]byte{}, lib.Prefixes.PrefixLockedStakeByValidatorAndStakerAndLockedAt...)
	_, lockedStakeEntries, err := lib.DBGetPaginatedKeysAndValuesForPrefix(
		fes.TXIndex.TXIndexChain.DB(), lockedStakeStartPrefix, lockedStakeValidForPrefix,
		0, -1, false, true)
	if err != nil {
		glog.Errorf("StartSupplyMonitoring: Error getting all locked stake entries")
	}
	for _, lockedStakeEntry := range lockedStakeEntries {
		lse := &lib.LockedStakeEntry{}
		if exists, err := lib.DecodeFromBytes(lse, bytes.NewReader(lockedStakeEntry)); !exists || err != nil {
			glog.Errorf("StartSupplyMonitoring: Error decoding locked stake entry: %v", err)
			continue
		}

		if !lse.LockedAmountNanos.IsUint64() {
			glog.Errorf("StartSupplyMonitoring: Locked amount is not a uint64")
			continue
		}
		totalSupply += lse.LockedAmountNanos.Uint64()
	}

	fes.TotalStakedNanos = totalStakeSupply
	fes.TotalStakedDESO = float64(totalStakeSupply) / float64(lib.NanosPerUnit)
	fes.TotalSupplyNanos = totalSupply
	fes.TotalSupplyDESO = float64(totalSupply) / float64(lib.NanosPerUnit)

	sort.Slice(richList, func(ii, jj int) bool {
		return richList[ii].BalanceNanos > richList[jj].BalanceNanos
	})

	endIdx := richListLength
	if len(richList) < richListLength {
		endIdx = len(richList)
	}

	richList = richList[:endIdx]

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

func (fes *APIServer) GetCountKeysWithDESO(ww http.ResponseWriter, req *http.Request) {
	if !fes.Config.RunSupplyMonitoringRoutine {
		_AddBadRequestError(ww, fmt.Sprintf("Supply Monitoring is not enabled on this node"))
		return
	}
	if err := json.NewEncoder(ww).Encode(fes.CountKeysWithDESO); err != nil {
		_AddBadRequestError(ww, fmt.Sprintf("GetCountKeysWithDESO: Error encoding response: %v", err))
		return
	}
}
