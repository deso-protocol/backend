package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"
	"github.com/bitclout/core/lib"

	"github.com/bitclout/backend/graph/generated"
	"github.com/bitclout/backend/graph/model"
)

func (r *mutationResolver) CreateTest(ctx context.Context, input *model.NewTest) (*model.Notification, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *notificationResolver) From(ctx context.Context, obj *model.Notification) (*model.User, error) {
	return For(ctx).UserLoader.Load(*obj.FromPublicKey)
}

func (r *notificationResolver) Other(ctx context.Context, obj *model.Notification) (*model.User, error) {
	return For(ctx).UserLoader.Load(*obj.OtherPublicKey)
}

func (r *queryResolver) Notifications(ctx context.Context, publicKey *string) ([]*model.Notification, error) {
	notifications, err := r.Postgres.GetNotifications(*publicKey)
	if err != nil {
		return nil, err
	}

	var result []*model.Notification
	for _, notification := range notifications {
		transactionHash := notification.TransactionHash.String()
		fromPublicKey := lib.PkToStringMainnet(notification.FromUser)
		otherPublicKey := lib.PkToStringMainnet(notification.OtherUser)
		notificationType := int(notification.Type)
		amount := float64(notification.Amount)
		timestamp := int(notification.Timestamp)

		var postHash string
		if notification.PostHash != nil {
			postHash = notification.PostHash.String()
		}

		result = append(result, &model.Notification{
			TransactionHash: &transactionHash,
			FromPublicKey:   &fromPublicKey,
			OtherPublicKey:  &otherPublicKey,
			Type:            &notificationType,
			Amount:          &amount,
			PostHash:        &postHash,
			Timestamp:       &timestamp,
		})
	}

	return result, nil
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Notification returns generated.NotificationResolver implementation.
func (r *Resolver) Notification() generated.NotificationResolver { return &notificationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type notificationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
