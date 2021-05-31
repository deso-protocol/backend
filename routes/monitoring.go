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
				if fes.StarterBitCloutSeed != "" {
					starterBitCloutBalance, err := fes.GetBalanceForSeed(fes.StarterBitCloutSeed)
					if err != nil {
						glog.Error("StartSeedBalancesMonitoring: Error getting balance for starter bitclout seed")
					} else {
						fes.backendServer.GetStatsdClient().Gauge(fmt.Sprintf("STARTER_BITCLOUT_BALANCE"), float64(starterBitCloutBalance), tags, 1)
					}
				}
				if fes.BuyBitCloutSeed != "" {
					buyBitCloutBalance, err := fes.GetBalanceForSeed(fes.BuyBitCloutSeed)
					if err != nil {
						glog.Error("StartSeedBalancesMonitoring: Error getting balance for buy bitclout seed")
					} else {
						fes.backendServer.GetStatsdClient().Gauge(fmt.Sprintf("BUY_BITCLOUT_BALANCE"), float64(buyBitCloutBalance), tags, 1)
					}
				}
			case <- fes.quit:
				break out
			}
		}
	}()
}
