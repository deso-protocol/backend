module github.com/deso-protocol/backend

go 1.20

replace github.com/deso-protocol/core => ../core/

require (
	cloud.google.com/go/storage v1.15.0
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/btcsuite/btcutil v1.0.2
	github.com/davecgh/go-spew v1.1.1
	github.com/deso-protocol/core v0.0.0-00010101000000-000000000000
	github.com/deso-protocol/go-deadlock v1.0.0
	github.com/dgraph-io/badger/v3 v3.2103.0
	github.com/fatih/structs v1.1.0
	github.com/golang-jwt/jwt/v4 v4.1.0
	github.com/golang/glog v1.0.0
	github.com/gorilla/mux v1.8.0
	github.com/h2non/bimg v1.1.5
	github.com/holiman/uint256 v1.1.1
	github.com/kevinburke/twilio-go v0.0.0-20210327194925-1623146bcf73
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.1.2
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe
	github.com/nyaruka/phonenumbers v1.0.69
	github.com/pkg/errors v0.9.1
	github.com/sendgrid/sendgrid-go v3.10.0+incompatible
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/tyler-smith/go-bip39 v1.1.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/api v0.46.0
	gopkg.in/DataDog/dd-trace-go.v1 v1.29.0
)

require (
	cloud.google.com/go v0.81.0 // indirect
	github.com/DataDog/datadog-go v4.5.0+incompatible // indirect
	github.com/DataDog/zstd v1.4.8 // indirect
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/bwesterb/go-ristretto v1.2.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/cloudflare/circl v1.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/decred/dcrd/lru v1.1.1 // indirect
	github.com/deso-protocol/go-merkle-tree v1.0.0 // indirect
	github.com/dgraph-io/ristretto v0.1.0 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/ethereum/go-ethereum v1.9.25 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/gernest/mention v2.0.0+incompatible // indirect
	github.com/git-chglog/git-chglog v0.0.0-20200414013904-db796966b373 // indirect
	github.com/go-pg/pg/v10 v10.10.0 // indirect
	github.com/go-pg/zerochecker v0.2.0 // indirect
	github.com/gofrs/uuid v4.0.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/flatbuffers v2.0.0+incompatible // indirect
	github.com/google/pprof v0.0.0-20210226084205-cbba55b83ad5 // indirect
	github.com/google/uuid v1.2.0 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kevinburke/go-types v0.0.0-20210723172823-2deba1f80ba7 // indirect
	github.com/kevinburke/rest v0.0.0-20210506044642-5611499aa33c // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mattn/go-colorable v0.1.9 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/goveralls v0.0.6 // indirect
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/oleiade/lane v1.0.1 // indirect
	github.com/pelletier/go-toml v1.7.0 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/robinjoseph08/go-pg-migrations/v3 v3.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/sendgrid/rest v2.6.4+incompatible // indirect
	github.com/shibukawa/configdir v0.0.0-20170330084843-e180dbdc8da0 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/spf13/afero v1.1.2 // indirect
	github.com/spf13/cast v1.3.0 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tinylib/msgp v1.1.2 // indirect
	github.com/tmthrgd/go-hex v0.0.0-20190904060850-447a3041c3bc // indirect
	github.com/tsuyoshiwada/go-gitcmd v0.0.0-20180205145712-5f1f5f9475df // indirect
	github.com/ttacon/builder v0.0.0-20170518171403-c099f663e1c2 // indirect
	github.com/ttacon/libphonenumber v1.2.1 // indirect
	github.com/unrolled/secure v1.0.8 // indirect
	github.com/urfave/cli v1.22.1 // indirect
	github.com/vmihailenco/bufpool v0.1.11 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.1 // indirect
	github.com/vmihailenco/tagparser v0.1.2 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	golang.org/x/lint v0.0.0-20201208152925-83fdc39ff7b5 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/oauth2 v0.0.0-20210427180440-81ed05c6b58c // indirect
	golang.org/x/sys v0.0.0-20211007075335-d3039528d8ac // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/time v0.0.0-20201208040808-7e3f01d25324 // indirect
	golang.org/x/tools v0.1.5 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210429181445-86c259c2b4ab // indirect
	google.golang.org/grpc v1.37.0 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
	gopkg.in/AlecAivazis/survey.v1 v1.8.7 // indirect
	gopkg.in/ini.v1 v1.51.0 // indirect
	gopkg.in/kyokomi/emoji.v1 v1.5.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	mellium.im/sasl v0.2.1 // indirect
)
