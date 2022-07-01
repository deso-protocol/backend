FROM golang:1.17-alpine3.16

RUN apk --no-cache add gcc g++ vips-dev upx

WORKDIR /usr/src/deso/core

COPY core/go.mod .
COPY core/go.sum .

WORKDIR /usr/src/deso/backend

COPY backend/go.mod .
COPY backend/go.sum .

RUN go mod download && go mod verify

WORKDIR /usr/src/deso/core

COPY core/cmd cmd
COPY core/desohash desohash
COPY core/lib lib
COPY core/migrate migrate

WORKDIR /usr/src/deso/backend

COPY backend/apis apis
COPY backend/cmd cmd
COPY backend/config config
COPY backend/countries countries
COPY backend/miner miner
COPY backend/routes routes
COPY backend/main.go .

RUN GOOS=linux go build -ldflags "-s -w" -o /usr/local/bin/deso-backend main.go
RUN upx /usr/local/bin/deso-backend

ENTRYPOINT ["go", "test", "-v", "github.com/deso-protocol/backend/routes"]
