#!/bin/bash

go run ./dao-coin-distribute.go \
  --deso-node=""\
  --nft-post-hash=e946cb33cf570faf2b61c5e791cfe43fe4a19cb8fc7a5ade0cee0b6c6d6f9417\
  --dao-coin-public-key=BC1YLhQmL6q5CLf9gdoE8VyocVPBdPGAL6n3GozjYWe5YYfvoBEeXd9\
  --dao-coin-distributor-mnemonic=""\
  --distribution-amount-dao-coin-base-units=1\
  --max-distribution-amount-dao-coin-base-units=0\
  --disable-dao-distributor-public-key-check=true
