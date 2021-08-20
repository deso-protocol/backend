package graph

import (
	"github.com/bitclout/core/lib"
)

type Resolver struct {
	Server   *lib.Server
	Postgres *lib.Postgres
}
