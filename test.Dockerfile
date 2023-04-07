FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update bash cmake git go gcc g++ make vips-dev

WORKDIR /deso/src

RUN git clone https://github.com/deso-protocol/core.git

WORKDIR /deso/src/core
RUN git pull

WORKDIR /deso/src/backend

COPY go.mod .
COPY go.sum .

RUN go mod download
RUN /deso/src/core/scripts/install-relic.sh

# include backend src
COPY apis      apis
COPY cmd       cmd
COPY miner     miner
COPY routes    routes
COPY countries countries
COPY config    config
COPY main.go   .

# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/backend main.go

ENTRYPOINT ["go", "test", "-tags", "relic", "-v", "github.com/deso-protocol/backend/routes"]
