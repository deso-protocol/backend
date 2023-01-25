#!/bin/bash

go run ./daodao-message-notify.go\
  --deso-node="https://node0.deso.org"\
  --keys-filename="fake_passwords.txt"\
  --messaged-users-json-filename=testrun_gold.json\
  --nft-post-hash=d7ad20c81880b90d794da27ab427697abf21f1f4bf708d1586fa0cc9972e4f05\
  --messenger-mnemonic="enroll mercy immense disorder tattoo area worth noble blouse rescue rather review"\
  --disable-messenger-public-key-check=true\
  --message-pretext="This is a testrun: "\
  --delay-milliseconds=1000\
  --testrun=false
