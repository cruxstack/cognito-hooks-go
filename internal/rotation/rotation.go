// Package rotation records when the hooks last replaced each user's password.
// Cognito doesn't record when a password was set (AdminGetUser's
// UserLastModifiedDate changes on any attribute update), so the
// PreAuthentication hook keeps its own record to decide whether a password
// was set before its cutoff.
//
// Records live in a DynamoDB table keyed by the user's sub:
//
//	sub (S, partition key)  replaced_at (S, RFC 3339 in UTC)
package rotation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Attribute names of a record.
const (
	// KeyAttribute is the table's partition key, a string.
	KeyAttribute = "sub"
	// ReplacedAtAttribute is when the password was last replaced.
	ReplacedAtAttribute = "replaced_at"
)

// Store reads and writes rotation records.
type Store interface {
	// LastReplaced returns when the user's password was last replaced, or
	// nil when it never was.
	LastReplaced(ctx context.Context, sub string) (*time.Time, error)
	// Record records that the user's password was replaced at t.
	Record(ctx context.Context, sub string, t time.Time) error
}

// DynamoDBAPI is the part of the DynamoDB API the store calls.
type DynamoDBAPI interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// DynamoDB stores records in a DynamoDB table.
type DynamoDB struct {
	Client DynamoDBAPI
	Table  string
}

var errNoSub = errors.New("the user has no sub")

// LastReplaced reads the user's record.
func (s DynamoDB) LastReplaced(ctx context.Context, sub string) (*time.Time, error) {
	if sub == "" {
		return nil, errNoSub
	}
	out, err := s.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:            aws.String(s.Table),
		Key:                  key(sub),
		ProjectionExpression: aws.String(ReplacedAtAttribute),
	})
	if err != nil {
		return nil, fmt.Errorf("get rotation record: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	v, ok := out.Item[ReplacedAtAttribute].(*types.AttributeValueMemberS)
	if !ok {
		return nil, fmt.Errorf("rotation record has no %s string", ReplacedAtAttribute)
	}
	t, err := time.Parse(time.RFC3339Nano, v.Value)
	if err != nil {
		return nil, fmt.Errorf("rotation record: %w", err)
	}
	return &t, nil
}

// Record writes the user's record, replacing an earlier one.
func (s DynamoDB) Record(ctx context.Context, sub string, t time.Time) error {
	if sub == "" {
		return errNoSub
	}
	item := key(sub)
	item[ReplacedAtAttribute] = &types.AttributeValueMemberS{Value: t.UTC().Format(time.RFC3339Nano)}
	if _, err := s.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.Table),
		Item:      item,
	}); err != nil {
		return fmt.Errorf("put rotation record: %w", err)
	}
	return nil
}

func key(sub string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{KeyAttribute: &types.AttributeValueMemberS{Value: sub}}
}
