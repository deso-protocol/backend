FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update bash cmake g++ gcc git make vips-dev

COPY --from=golang:1.22-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /deso/src

COPY backend/go.mod backend/
COPY backend/go.sum backend/
COPY core/go.mod core/
COPY core/go.sum core/

WORKDIR /deso/src/backend

RUN go mod download

# include backend src
COPY backend/apis      apis
COPY backend/config    config
COPY backend/cmd       cmd
COPY backend/miner     miner
COPY backend/routes    routes
COPY backend/countries countries
COPY backend/main.go   .

# include core src
COPY core/bls         ../core/bls
COPY core/cmd         ../core/cmd
COPY core/collections ../core/collections
COPY core/consensus   ../core/consensus
COPY core/desohash    ../core/desohash
COPY core/lib         ../core/lib
COPY core/migrate     ../core/migrate

# build backend
#RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/backend main.go
RUN GOOS=linux go build -mod=mod -gcflags="all=-N -l" -o bin/backend main.go

# create tiny image
FROM alpine:latest

RUN apk add --update vips-dev

# Install necessary dependencies, including Go, git, and build tools
RUN apk add --no-cache go git gcc g++ 

ENV GOPATH /go
# Ensure both /usr/local/go/bin and $GOPATH/bin are in the PATH
ENV PATH="/usr/local/go/bin:$GOPATH/bin:${PATH}"

# Now that PATH is correctly set, install Delve
RUN go install github.com/go-delve/delve/cmd/dlv@latest

COPY --from=backend /deso/src/backend/bin/backend /deso/bin/backend

ENTRYPOINT ["dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--continue", "--accept-multiclient", "exec", "/deso/bin/backend"]
