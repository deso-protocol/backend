package routes

import (
	"fmt"
	"github.com/golang/glog"
	"time"
)

func (fes *APIServer) StartSeedBalancesMonitoring() {
	go func() {
	out:
		for {
			select {
			case <- time.After(5 * time.Second):
				if fes.backendServer.GetStatsdClient() == nil {
					return
				}
				tags := []string{}
				fes.LogBalanceForSeed(fes.StarterBitCloutSeed, "STARTER_BITCLOUT", tags)
				fes.LogBalanceForSeed(fes.BuyBitCloutSeed, "BUY_BITCLOUT", tags)
			case <- fes.quit:
				break out
			}
		}
	}()
}

func (fes *APIServer) LogBalanceForSeed(seed string, seedName string, tags []string) {
	if seed == "" {
		return
	}
	balance, err := fes.GetBalanceForSeed(seed)
	if err != nil {
		glog.Errorf("LogBalanceForSeed: Error getting balance for %v seed", seedName)
		return
	}
	if err = fes.backendServer.GetStatsdClient().Gauge(fmt.Sprintf("%v_BALANCE", seedName), float64(balance), tags, 1); err != nil {
		glog.Errorf("LogBalanceForSeed: Error logging balance to datadog for %v seed", seedName)
	}
}
