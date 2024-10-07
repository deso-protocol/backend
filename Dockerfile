FROM alpine:latest AS backend

RUN apk update
RUN apk upgrade
RUN apk add --update bash cmake g++ gcc git make vips-dev

COPY --from=golang:1.20-alpine /usr/local/go/ /usr/local/go/
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

# Install Delve debugger, specifying the installation path explicitly
ENV GOPATH=/root/go
RUN go install github.com/go-delve/delve/cmd/dlv@v1.22.1

# build backend
#RUN GOOS=linux go build -mod=mod -a -installsuffix cgo -o bin/backend main.go
# NOTE: We're running an unoptimized build here because it makes it possible to attach
# a debugger directly to any of our running nodes. We take this trade-off for now.
RUN GOOS=linux go build -gcflags="all=-N -l" -mod=mod -a -installsuffix cgo -o bin/backend main.go


# create tiny image
FROM alpine:latest

RUN apk add --update vips-dev

# Copy the compiled binary and the Delve binary from the build stage
COPY --from=backend /deso/src/backend/bin/backend /deso/bin/backend
# Updated path according to the installation path
COPY --from=backend /root/go/bin/dlv /bin/

# Expose the port Delve will listen on
EXPOSE 2345

# NOTE: The ENTRYPOINT is overwritten when a node is deployed to Kubernetes so this
# mainly serves as an example.
#ENTRYPOINT ["/deso/bin/backend", "run"]
ENTRYPOINT ["/bin/dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/deso/bin/backend", "--continue"]
