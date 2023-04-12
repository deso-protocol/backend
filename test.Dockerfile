FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update go gcc g++ vips-dev git

WORKDIR /deso/src

RUN git clone https://github.com/deso-protocol/core.git

WORKDIR /deso/src/core
ARG CORE_BRANCH=main
RUN if ["$CORE_BRANCH" != "main"]; then git checkout main ; else git branch -D "$CORE_BRANCH" && git checkout -b "$CORE_BRANCH" origin/"$CORE_BRANCH"; fi
RUN git pull

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

ENTRYPOINT ["go", "test", "-v", "github.com/deso-protocol/backend/routes"]
