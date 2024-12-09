/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dynamodb

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	dbexpr "github.com/aws/aws-sdk-go/service/dynamodb/expression"
	spi "github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// expressionTagNameOnlyLength     = 1
	// expressionTagNameAndValueLength = 2

	invalidTagName  = `"%s" is an invalid tag name since it contains one or more ':' characters`
	invalidTagValue = `"%s" is an invalid tag value since it contains one or more ':' characters`
)

var (
	errEmptyKey                     = errors.New("key cannot be empty")
	errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
		"it must be in the following format: TagName:TagValue")
	errIteratorExhausted = errors.New("iterator is exhausted")
)

// Provider represents an in-memory implementation of the spi.Provider interface.
type Provider struct {
	client *dynamodb.DynamoDB
	tables map[string]*dynamodbTable
	lock   sync.RWMutex
}

// NewProvider instantiates a new in-memory storage Provider.
func NewProvider() *Provider {
	// Initialize a session that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials
	// and region from the shared configuration file ~/.aws/config.
	stage := os.Getenv("STAGE")
	config := aws.Config{}

	if stage == "local" {
		endpoint := "http://host.docker.internal:8100"
		config = aws.Config{
			Endpoint:    &endpoint,
			Credentials: credentials.NewStaticCredentials("DEFAULT_ACCESS_KEY", "DEFAULT_SECRET", ""),
		}
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config:            config,
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	client := dynamodb.New(sess)
	if client == nil {
		return nil
	}

	return &Provider{
		client: client,
		tables: make(map[string]*dynamodbTable),
	}
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
func (p *Provider) OpenStore(name string) (spi.Store, error) {
	if name == "" {
		return nil, fmt.Errorf("store name cannot be empty")
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	fmt.Printf("Opening store %s\n", name)
	tableName := tableName(name)

	store := p.tables[tableName]
	if store != nil {
		return store, nil
	}

	describeTableOutput, err := p.client.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: &tableName,
	})

	if err != nil {
		fmt.Printf("OpenStore error: %v\n", err)
		fmt.Printf("Please ensure %s is defined in serverless.yml", tableName)
		return nil, err
	}

	p.tables[tableName] = &dynamodbTable{
		name:   *describeTableOutput.Table.TableName,
		client: p.client,
	}

	return p.tables[tableName], nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping spi.ErrStoreNotFound will be returned.
func (p *Provider) SetStoreConfig(name string, config spi.StoreConfiguration) error {
	for _, tagName := range config.TagNames {
		if strings.Contains(tagName, ":") {
			return fmt.Errorf(invalidTagName, tagName)
		}
	}

	tableName := tableName(name)

	p.lock.Lock()
	defer p.lock.Unlock()

	store := p.tables[tableName]
	if store == nil {
		return spi.ErrStoreNotFound
	}

	store.config = config

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping spi.ErrStoreNotFound will be returned.
func (p *Provider) GetStoreConfig(name string) (spi.StoreConfiguration, error) {
	tableName := tableName(name)

	store := p.tables[tableName]
	if store == nil {
		return spi.StoreConfiguration{}, spi.ErrStoreNotFound
	}

	return store.config, nil
}

// GetOpenStores returns all currently open stores.
func (p *Provider) GetOpenStores() []spi.Store {
	p.lock.RLock()
	defer p.lock.RUnlock()

	openStores := make([]spi.Store, len(p.tables))

	var counter int

	for _, table := range p.tables {
		openStores[counter] = table
		counter++
	}

	return openStores
}

// Close closes all stores created under this store provider.
func (p *Provider) Close() error {
	// TODO
	p.lock.Lock()
	defer p.lock.Unlock()

	return nil
}

type dbEntry struct {
	Key   string
	Value []byte
	Tags  string
}

type dynamodbTable struct {
	name   string
	client *dynamodb.DynamoDB
	config spi.StoreConfiguration
}

// Put stores the key + value pair along with the (optional) tags.
func (m *dynamodbTable) Put(key string, value []byte, tags ...spi.Tag) error {
	if key == "" {
		return errEmptyKey
	}

	fmt.Printf("Storing %s with value %s, tags %s\n", key, value, tags)

	if value == nil {
		return errors.New("value cannot be nil")
	}

	strTags, err := marshalTags(tags)
	if err != nil {
		return err
	}

	avItem, err := dynamodbattribute.MarshalMap(dbEntry{
		Key:   key,
		Value: value,
		Tags: strTags,
	})
	if err != nil {
		fmt.Printf("Put error: %s\n", err)
	}

	_, err = m.client.PutItem(&dynamodb.PutItemInput{
		TableName: &m.name,
		Item:      avItem,
	})
	if err != nil {
		fmt.Printf("Put error: %s\n", err)
	}

	return err
}

// Get fetches the value associated with the given key.
// If key cannot be found, then an error wrapping spi.ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (m *dynamodbTable) Get(key string) ([]byte, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	fmt.Printf("Fetching key %s\n", key)

	result, err := m.client.GetItem(&dynamodb.GetItemInput{
		TableName: &m.name,
		Key: map[string]*dynamodb.AttributeValue{
			"Key": {
				S: &key,
			},
		},
	})

	if err != nil {
		fmt.Printf("Get error: %s\n", err)
		return nil, err
	}

	if result.Item == nil {
		return nil, spi.ErrDataNotFound
	}

	var item dbEntry
	if err := dynamodbattribute.UnmarshalMap(result.Item, &item); err != nil {
		fmt.Printf("Get error: %s\n", err)
		return nil, err
	}

	return item.Value, nil
}

// Get fetches all tags associated with the given key.
// If key cannot be found, then an error wrapping spi.ErrDataNotFound will be returned.
// If key is empty, then an error will be returned.
func (m *dynamodbTable) GetTags(key string) ([]spi.Tag, error) {
	if key == "" {
		return nil, errEmptyKey
	}

	result, err := m.client.GetItem(&dynamodb.GetItemInput{
		TableName: &m.name,
		Key: map[string]*dynamodb.AttributeValue{
			"Key": {
				S: &key,
			},
		},
	})

	if err != nil {
		fmt.Printf("GetTags error: %s\n", err)
		return nil, err
	}

	if result.Item == nil {
		return nil, spi.ErrDataNotFound
	}

	var item dbEntry
	if err := dynamodbattribute.UnmarshalMap(result.Item, &item); err != nil {
		fmt.Printf("GetTags error: %s\n", err)
		return nil, err
	}

	return unmarshalTags(item.Tags), nil
}

func marshalTags(tags []spi.Tag) (string, error) {
	var sb strings.Builder
	for _, tag := range tags {
		if strings.Contains(tag.Name, ":") || strings.Contains(tag.Name, ",") {
			return "", fmt.Errorf(invalidTagName, tag.Name)
		}

		if strings.Contains(tag.Value, ":") || strings.Contains(tag.Name, ",") {
			return "", fmt.Errorf(invalidTagValue, tag.Value)
		}

		sb.WriteString(fmt.Sprintf("%s:%s,", tag.Name, tag.Value))
	}

	return "[" + strings.TrimRight(sb.String(), ",") + "]", nil
}

func unmarshalTags(tags string) []spi.Tag {
	parsedTags := make([]spi.Tag, 1)
	tagValueStr := strings.Split(strings.Trim(tags, "[]"), ",")
	for _, tvStr := range tagValueStr {
		tv := strings.Split(tvStr, ":")
		parsedTags = append(parsedTags, spi.Tag{
			Name: tv[0],
			Value: tv[1],
		})
	}

	return parsedTags
}

// GetBulk fetches the values associated with the given keys.
// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
// If any of the given keys are empty, then an error will be returned.
func (m *dynamodbTable) GetBulk(keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("keys slice must contain at least one key")
	}

	fmt.Printf("Bulk getting keys %s\n", keys)

	for _, key := range keys {
		if key == "" {
			return nil, errEmptyKey
		}
	}

	values := make([][]byte, len(keys))

	for i, key := range keys {
		var err error
		values[i], err = m.Get(key)
		if err != nil {
			fmt.Printf("GetBulk error: %s\n", err)
			return values, err
		}
	}

	return values, nil
}

// Query returns all data that satisfies the expression. Expression format: TagName:TagValue.
// If TagValue is not provided, then all data associated with the TagName will be returned.
// For now, expression can only be a single tag Name + Value pair.
// None of the current query options are supported
// spi.WithPageSize will simply be ignored since it only relates to performance and not the actual end result.
// spi.WithInitialPageNum and spi.WithSortOrder will result in an error being returned since those options do
// affect the results that the Iterator returns.
func (m *dynamodbTable) Query(expression string, options ...spi.QueryOption) (spi.Iterator, error) {
	err := checkForUnsupportedQueryOptions(options)
	if err != nil {
		fmt.Printf("Query error: %s\n", err)
		return nil, err
	}

	// TODO

	fmt.Printf("Querying %s\n", expression)

	if expression == "" {
		return nil, errInvalidQueryExpressionFormat
	}

	expr, err := dbexpr.NewBuilder().WithFilter(dbexpr.Name("Tags").Contains(expression)).Build()
	if err != nil {
		fmt.Printf("Query error: %s\n", err)
		return nil, err
	}

	scanOutput, err := m.client.Scan(&dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		TableName:                 &m.name,
	})
	if err != nil {
		fmt.Printf("Query error: %s\n", err)
		return nil, err
	}

	return &itemIterator{
		ScanOutput: scanOutput,
		idx: -1,
	}, nil
}

// Delete deletes the key + value pair (and all tags) associated with key.
// If key is empty, then an error will be returned.
func (m *dynamodbTable) Delete(k string) error {
	if k == "" {
		return errEmptyKey
	}

	fmt.Printf("Delete key %s\n", k)

	_, err := m.client.DeleteItem(&dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Key": {
				S: &k,
			},
		},
		TableName: &m.name,
	})

	return err
}

// Batch performs multiple Put and/or Delete operations in order.
// If any of the given keys are empty, then an error will be returned.
func (m *dynamodbTable) Batch(operations []spi.Operation) error {
	if len(operations) == 0 {
		return errors.New("batch requires at least one operation")
	}

	fmt.Printf("Batching...\n")

	for _, operation := range operations {
		if operation.Key == "" {
			return errEmptyKey
		}
	}

	for _, operation := range operations {
		if operation.Value == nil {
			m.Delete(operation.Key)
			continue
		}

		m.Put(operation.Key, operation.Value, operation.Tags...)
	}

	return nil
}

// Close closes this store object. All data within the store is deleted.
func (m *dynamodbTable) Close() error {
	// TODO

	return nil
}

// memStore doesn't queue values, so there's never anything to flush.
func (m *dynamodbTable) Flush() error {
	// TODO
	return nil
}

// memIterator represents a snapshot of some set of entries in a memStore.
type itemIterator struct {
	*dynamodb.ScanOutput
	idx int64
}

// Next moves the pointer to the next entry in the iterator. It returns false if the iterator is exhausted.
func (m *itemIterator) Next() (bool, error) {
	if m.idx == *m.Count-1 || *m.Count == 0 {
		return false, nil
	}

	m.idx++

	return true, nil
}

// Key returns the key of the current entry.
func (m *itemIterator) Key() (string, error) {
	if *m.Count == 0 {
		return "", errIteratorExhausted
	}

	var item dbEntry
	err := dynamodbattribute.UnmarshalMap(m.Items[m.idx], &item)
	return item.Key, err
}

// Value returns the value of the current entry.
func (m *itemIterator) Value() ([]byte, error) {
	if *m.Count == 0 {
		return nil, errIteratorExhausted
	}

	var item dbEntry
	err := dynamodbattribute.UnmarshalMap(m.Items[m.idx], &item)
	return item.Value, err
}

// Tags returns the tags associated with the key of the current entry.
func (m *itemIterator) Tags() ([]spi.Tag, error) {
	if *m.Count == 0 {
		return nil, errIteratorExhausted
	}

	var item dbEntry
	err := dynamodbattribute.UnmarshalMap(m.Items[m.idx], &item)
	return unmarshalTags(item.Tags), err
}

func (m *itemIterator) TotalItems() (int, error) {
	return int(*m.Count), nil
}

// Close is a no-op, since there's nothing to close for a memIterator.
func (m *itemIterator) Close() error {
	return nil
}

func getQueryOptions(options []spi.QueryOption) spi.QueryOptions {
	var queryOptions spi.QueryOptions

	for _, option := range options {
		option(&queryOptions)
	}

	return queryOptions
}

func checkForUnsupportedQueryOptions(options []spi.QueryOption) error {
	querySettings := getQueryOptions(options)

	if querySettings.InitialPageNum != 0 {
		return errors.New("in-memory provider does not currently support " +
			"setting the initial page number of query results")
	}

	if querySettings.SortOptions != nil {
		return errors.New("in-memory provider does not currently support custom sort options for query results")
	}

	return nil
}

// Helper Function slightly similar to serverless-util in typescript
// https://github.com/scaffoldly/serverless-util/blob/main/src/db.ts#L8-L10
func tableName(name string) string {
	stage := os.Getenv("STAGE")
	serviceName := os.Getenv("SERVICE_NAME")

	return fmt.Sprintf("%s-%s-%s", stage, serviceName, strings.ToLower(name))
}
