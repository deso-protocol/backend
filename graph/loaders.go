package graph

import (
	"context"
	"github.com/bitclout/backend/dataloader"
	"github.com/bitclout/backend/graph/model"
	"github.com/bitclout/core/lib"
	"net/http"
	"time"
)

const loadersKey = "dataloaders"

// Loaders holds references to the individual dataloaders.
type Loaders struct {
	UserLoader *dataloader.UserLoader
}

func newLoaders(resolver *Resolver) *Loaders {
	return &Loaders{
		UserLoader: dataloader.NewUserLoader(*NewUserLoaderConfig(resolver)),
	}
}

func NewUserLoaderConfig(resolver *Resolver) *dataloader.UserLoaderConfig {
	return &dataloader.UserLoaderConfig{
		Wait:     1 * time.Millisecond,
		MaxBatch: 100,
		Fetch: func(keys []string) ([]*model.User, []error) {
			utxoView, err := resolver.Server.GetMempool().GetAugmentedUniversalView()
			if err != nil {
				return nil, []error{err}
			}

			var result []*model.User
			for _, publicKey := range keys {
				profileEntry := utxoView.GetProfileEntryForPublicKey(lib.MustBase58CheckDecode(publicKey))
				if profileEntry == nil {
					result = append(result, &model.User{
						Name: publicKey,
					})
				} else {
					result = append(result, &model.User{
						Name: string(profileEntry.Username),
					})
				}
			}

			return result, nil
		},
	}
}

func Middleware(next http.Handler, resolver *Resolver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loadersKey, newLoaders(resolver))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func For(ctx context.Context) *Loaders {
	return ctx.Value(loadersKey).(*Loaders)
}
