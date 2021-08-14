module github.com/bitclout/backend

go 1.16

replace github.com/bitclout/core => ../core/

replace github.com/golang/glog => ../core/third_party/github.com/golang/glog

replace github.com/laser/go-merkle-tree => ../core/third_party/github.com/laser/go-merkle-tree

replace github.com/sasha-s/go-deadlock => ../core/third_party/github.com/sasha-s/go-deadlock

require (
	cloud.google.com/go/storage v1.15.0
	github.com/bitclout/core v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/btcsuite/btcutil v1.0.2
	github.com/dgraph-io/badger/v3 v3.2103.0
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1
	github.com/fatih/structs v1.1.0
	github.com/gofrs/uuid v4.0.0+incompatible // indirect
	github.com/golang/glog v0.0.0-20210429001901-424d2337a529
	github.com/gorilla/mux v1.8.0
	github.com/h2non/bimg v1.1.5
	github.com/kevinburke/go-types v0.0.0-20210723172823-2deba1f80ba7 // indirect
	github.com/kevinburke/rest v0.0.0-20210506044642-5611499aa33c // indirect
	github.com/kevinburke/twilio-go v0.0.0-20210327194925-1623146bcf73
	github.com/mitchellh/go-homedir v1.1.0
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe
	github.com/nyaruka/phonenumbers v1.0.69
	github.com/pkg/errors v0.9.1
	github.com/sasha-s/go-deadlock v0.2.0
	github.com/sendgrid/rest v2.6.4+incompatible // indirect
	github.com/sendgrid/sendgrid-go v3.10.0+incompatible // indirect
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/ttacon/builder v0.0.0-20170518171403-c099f663e1c2 // indirect
	github.com/ttacon/libphonenumber v1.2.1 // indirect
	github.com/tyler-smith/go-bip39 v1.1.0
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a // indirect
	google.golang.org/api v0.46.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.29.0
)
