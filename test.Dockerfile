FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update bash cmake g++ gcc git make vips-dev

COPY --from=golang:1.20-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"

# Declare an ARG for the branch name with a default value of "main"
ARG BRANCH_NAME=main

WORKDIR /deso/src

RUN git clone https://github.com/deso-protocol/core.git

WORKDIR /deso/src/core
RUN git pull

RUN go mod download

# Try to checkout to the specified branch. If it fails, checkout main.
RUN git checkout ${BRANCH_NAME} || (echo "Branch ${BRANCH_NAME} not found. Falling back to main." && git checkout main)

# Try to checkout to the specified branch. If it fails, checkout main.
RUN git checkout ${BRANCH_NAME} || (echo "Branch ${BRANCH_NAME} not found. Falling back to main." && git checkout main)

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
