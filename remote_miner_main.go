package main

import (
	"flag"
	"github.com/bitclout/backend/miner"
	"log"

	"github.com/golang/glog"
)

var (
	flagRemoteBlockProducer = flag.String(
		"remote_block_producer", "http://localhost:17001",
		"The HTTP(S)://IP:PORT or HTTP(S)://DOMAIN:PORT of a node that is running a block producer. "+
			"This node will be used to get block templates that the miner can hash on")
	flagMinerPublicKey = flag.String(
		"miner_public_key", "",
		"Indicates where to send "+
			"block rewards from mining blocks. Public key must be "+
			"a compressed ECDSA public key formatted as a base58Check string.")
	flagNumMiningThreads = flag.Int64(
		"num_mining_threads", 0,
		"How many threads to run for mining. If set to zero, which is the default, "+
			"then the number of threads available to the system will be used.")
	flagIterationsPerCycle = flag.Int64(
		"iterations_per_cycle", 1000,
		"How many iterations to run before we check whether or not we've hit the "+
			"difficulty target. This flag isn't very important anymore, and "+
			"setting it lower or higher shouldn't affect performance very much.")
	flagTemplateRefreshIntervalSeconds = flag.Float64(
		"template_refresh_interval_seconds", 5.0,
		"How often the BlockProducer is queried for a fresh set of templates.")
)

func main() {
	flag.Parse()

	// Set up logging.
	glog.Init()
	log.Printf("Logging to folder: %s", glog.GlogFlags.LogDir)
	log.Printf("Symlink to latest: %s", glog.GlogFlags.Symlink)
	log.Println("To log output on commandline, run with -alsologtostderr")
	glog.CopyStandardLogTo("INFO")

	if *flagMinerPublicKey == "" {
		panic("--miner_public_key is required. Must be a Base58Check " +
			"public key (starts with BC/tBC depending on mainnet/testnet)")
	}

	// Create a RemoteMiner
	remoteMiner := miner.NewRemoteMiner(
		*flagRemoteBlockProducer, *flagMinerPublicKey, *flagNumMiningThreads,
		*flagIterationsPerCycle, *flagTemplateRefreshIntervalSeconds)

	remoteMiner.Start()
}
