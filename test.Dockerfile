FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update bash cmake g++ gcc git make vips-dev

COPY --from=golang:1.20-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /deso/src

RUN git clone https://github.com/deso-protocol/core.git

WORKDIR /deso/src/core
RUN git pull && \
    git checkout mf/rename-validator-voting-signature && \
    git pull origin mf/rename-validator-voting-signature # TODO: Revert to `git pull` once core PR is merged.

RUN go mod download
RUN ./scripts/install-relic.sh

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
COPY config    config
COPY main.go   .

# build backend
RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/backend main.go

ENTRYPOINT ["go", "test", "-tags", "relic", "-v", "github.com/deso-protocol/backend/routes"]
