package rotation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type fakeDynamoDB struct {
	get  *dynamodb.GetItemInput
	put  *dynamodb.PutItemInput
	item map[string]types.AttributeValue
	err  error
}

func (f *fakeDynamoDB) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.get = in
	if f.err != nil {
		return nil, f.err
	}
	return &dynamodb.GetItemOutput{Item: f.item}, nil
}

func (f *fakeDynamoDB) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.put = in
	if f.err != nil {
		return nil, f.err
	}
	return &dynamodb.PutItemOutput{}, nil
}

func str(m map[string]types.AttributeValue, k string) string {
	if v, ok := m[k].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func TestRecordThenRead(t *testing.T) {
	f := &fakeDynamoDB{}
	s := DynamoDB{Client: f, Table: "rotations"}
	at := time.Date(2026, 11, 4, 12, 30, 0, 123, time.FixedZone("EST", -5*3600))

	if err := s.Record(context.Background(), "sub-1", at); err != nil {
		t.Fatal(err)
	}
	if aws.ToString(f.put.TableName) != "rotations" || str(f.put.Item, "sub") != "sub-1" {
		t.Errorf("put = %+v", f.put)
	}
	if got := str(f.put.Item, "replaced_at"); got != "2026-11-04T17:30:00.000000123Z" {
		t.Errorf("replaced_at = %q, want UTC RFC 3339", got)
	}

	f.item = f.put.Item
	got, err := s.LastReplaced(context.Background(), "sub-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Equal(at) {
		t.Errorf("LastReplaced() = %v, want %v", got, at)
	}
	if aws.ToString(f.get.TableName) != "rotations" || str(f.get.Key, "sub") != "sub-1" {
		t.Errorf("get = %+v", f.get)
	}
}

func TestLastReplaced_NoRecord(t *testing.T) {
	got, err := DynamoDB{Client: &fakeDynamoDB{}, Table: "rotations"}.LastReplaced(context.Background(), "sub-1")
	if got != nil || err != nil {
		t.Errorf("LastReplaced() = %v, %v; want nil, nil", got, err)
	}
}

func TestErrors(t *testing.T) {
	ctx := context.Background()
	tests := map[string]func() error{
		"get fails": func() error {
			_, err := DynamoDB{Client: &fakeDynamoDB{err: errors.New("ProvisionedThroughputExceededException")}}.LastReplaced(ctx, "sub-1")
			return err
		},
		"put fails": func() error {
			return DynamoDB{Client: &fakeDynamoDB{err: errors.New("AccessDeniedException")}}.Record(ctx, "sub-1", time.Now())
		},
		"record without a time": func() error {
			_, err := DynamoDB{Client: &fakeDynamoDB{item: map[string]types.AttributeValue{
				"sub": &types.AttributeValueMemberS{Value: "sub-1"},
			}}}.LastReplaced(ctx, "sub-1")
			return err
		},
		"record with an invalid time": func() error {
			_, err := DynamoDB{Client: &fakeDynamoDB{item: map[string]types.AttributeValue{
				"replaced_at": &types.AttributeValueMemberS{Value: "yesterday"},
			}}}.LastReplaced(ctx, "sub-1")
			return err
		},
		"read without a sub": func() error {
			_, err := DynamoDB{Client: &fakeDynamoDB{}}.LastReplaced(ctx, "")
			return err
		},
		"record without a sub": func() error {
			return DynamoDB{Client: &fakeDynamoDB{}}.Record(ctx, "", time.Now())
		},
	}
	for name, fn := range tests {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
