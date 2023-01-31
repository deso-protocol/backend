FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update go gcc g++ vips-dev git

WORKDIR /deso/src

RUN git clone git@github.com:deso-protocol/core.git
#
#WORKDIR /deso/src/core
#COPY go.mod .
#COPY go.sum .
#
## include core src
#COPY desohash desohash
#COPY cmd       cmd
#COPY lib       lib
#COPY test_data test_data
#COPY migrate   migrate
#COPY main.go   .

WORKDIR /deso/src/backend

COPY go.mod .
COPY go.sum .

RUN go mod download

# include backend src
COPY apis      apis
COPY cmd       cmd
COPY miner     miner
COPY routes    routes
COPY countries countries
COPY main.go   .



# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/backend main.go

ENTRYPOINT ["go", "test", "-v", "github.com/deso-protocol/backend/routes"]
