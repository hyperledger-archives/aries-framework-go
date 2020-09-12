/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	// Add as per the documentation - https://github.com/go-sql-driver/mysql
	_ "github.com/go-sql-driver/mysql"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

// Provider represents a MySQL DB implementation of the storage.Provider interface.
type Provider struct {
	dbURL    string
	db       *sql.DB
	dbs      map[string]*sqlDBStore
	dbPrefix string
	sync.RWMutex
}

type sqlDBStore struct {
	db        *sql.DB
	tableName string
	dbName    string
}

type result struct {
	key   string
	value []byte
}

const (
	blankDBPathErrMsg         = "DB URL for new mySQL DB provider can't be blank"
	failToCloseProviderErrMsg = "failed to close provider"
	tablePrefix               = "t_"
	sqlDBNotFound             = "no rows"
	createDBQuery             = "CREATE DATABASE IF NOT EXISTS `%s`"
	useDBQuery                = "USE `%s`"
)

// Option configures the couchdb provider.
type Option func(opts *Provider)

// WithDBPrefix option is for adding prefix to db name.
func WithDBPrefix(dbPrefix string) Option {
	return func(opts *Provider) {
		opts.dbPrefix = dbPrefix
	}
}

// NewProvider instantiates Provider.
func NewProvider(dbPath string, opts ...Option) (*Provider, error) {
	if dbPath == "" {
		return nil, errors.New(blankDBPathErrMsg)
	}

	// Example DB Path root:my-secret-pw@tcp(127.0.0.1:3306)/
	db, err := sql.Open("mysql", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failure while pinging MySQL at url %s : %w", dbPath, err)
	}

	p := &Provider{
		dbURL: dbPath,
		db:    db,
		dbs:   map[string]*sqlDBStore{},
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// OpenStore opens and returns new db for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.Lock()
	defer p.Unlock()

	if name == "" {
		return nil, errors.New("store name is required")
	}

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	// Check cache first
	cachedStore, existsInCache := p.dbs[name]
	if existsInCache {
		return cachedStore, nil
	}

	// creating the database
	_, err := p.db.Exec(fmt.Sprintf(createDBQuery, name))
	if err != nil {
		return nil, fmt.Errorf("failed to create db %s: %w", name, err)
	}

	// Opening new db connection
	newDBConn, err := sql.Open("mysql", p.dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection %s: %w", p.dbURL, err)
	}

	// Use query is used to select the created database without this DDL operations are not permitted
	_, err = newDBConn.Exec(fmt.Sprintf(useDBQuery, name))
	if err != nil {
		return nil, fmt.Errorf("failed to use db %s: %w", name, err)
	}

	tableName := tablePrefix + name
	// TODO: Issue-1940 Store the hashed key to control the width of the key varchar column
	createTableStmt := "CREATE Table IF NOT EXISTS `" + tableName +
		"` (`key` varchar(255) NOT NULL ,`value` BLOB, PRIMARY KEY (`key`));"

	// creating key-value table inside the database
	_, err = newDBConn.Exec(createTableStmt)
	if err != nil {
		return nil, fmt.Errorf("failed to create table %s: %w", tableName, err)
	}

	store := &sqlDBStore{
		db:        newDBConn,
		tableName: tableName,
		dbName:    name,
	}

	p.dbs[name] = store

	return store, nil
}

// Close closes the provider.
func (p *Provider) Close() error {
	p.Lock()
	defer p.Unlock()

	for _, store := range p.dbs {
		err := store.db.Close()
		if err != nil {
			return fmt.Errorf(failToCloseProviderErrMsg+": %w", err)
		}
	}

	if err := p.db.Close(); err != nil {
		return err
	}

	p.dbs = make(map[string]*sqlDBStore)

	return nil
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	p.Lock()
	defer p.Unlock()

	if p.dbPrefix != "" {
		name = p.dbPrefix + "_" + name
	}

	store, exists := p.dbs[name]
	if !exists {
		return nil
	}

	delete(p.dbs, name)

	return store.db.Close()
}

// Put stores the key and the value.
func (s *sqlDBStore) Put(k string, v []byte) error {
	if k == "" || v == nil {
		return errors.New("key and value are mandatory")
	}

	// Use query is used to select the created database without this DDL operations are not permitted
	_, err := s.db.Exec(fmt.Sprintf(useDBQuery, s.dbName))
	if err != nil {
		return fmt.Errorf("failed to use db %s: %w", s.dbName, err)
	}

	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	createStmt := "INSERT INTO `" + s.tableName + "` VALUES (?, ?) ON DUPLICATE KEY UPDATE value=?"
	// executing the prepared insert statement
	_, err = s.db.Exec(createStmt, k, v, v)
	if err != nil {
		return fmt.Errorf("failed to insert key and value record into %s %w ", s.tableName, err)
	}

	return nil
}

// Get fetches the value based on key.
func (s *sqlDBStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, storage.ErrKeyRequired
	}

	// Use query is used to select the created database without this DDL operations are not permitted
	_, err := s.db.Exec(fmt.Sprintf(useDBQuery, s.dbName))
	if err != nil {
		return nil, fmt.Errorf("failed to use db %s: %w", s.dbName, err)
	}

	var value []byte

	// select query to fetch the record by key
	err = s.db.QueryRow("SELECT `value` FROM `"+s.tableName+"` "+
		" WHERE `key` = ?", k).Scan(&value)
	if err != nil {
		if strings.Contains(err.Error(), sqlDBNotFound) {
			return nil, storage.ErrDataNotFound
		}

		return nil, fmt.Errorf("failed to get row %w", err)
	}

	return value, nil
}

// Delete will delete record with k key.
func (s *sqlDBStore) Delete(k string) error {
	if k == "" {
		return storage.ErrKeyRequired
	}

	// Use query is used to select the created database without this DDL operations are not permitted
	_, err := s.db.Exec(fmt.Sprintf(useDBQuery, s.dbName))
	if err != nil {
		return fmt.Errorf("failed to use db %s: %w", s.dbName, err)
	}

	// delete query to delete the record by key
	_, err = s.db.Exec("DELETE FROM `"+s.tableName+"` WHERE `key`= ?", k)

	if err != nil {
		return fmt.Errorf("failed to delete row %w", err)
	}

	return nil
}

type sqlDBResultsIterator struct {
	resultRows *sql.Rows
	result     result
	err        error
}

func (s *sqlDBStore) Iterator(startKey, endKey string) storage.StoreIterator {
	// reference : https://dev.mysql.com/doc/refman/8.0/en/fulltext-boolean.html
	if strings.Contains(endKey, storage.EndKeySuffix) {
		endKey = strings.ReplaceAll(endKey, storage.EndKeySuffix, "*")
		endKey = strings.ReplaceAll(endKey, "_", `\_`)
	}

	// Use query is used to select the created database without this DDL operations are not permitted
	_, err := s.db.Exec(fmt.Sprintf(useDBQuery, s.dbName))
	if err != nil {
		return &sqlDBResultsIterator{
			err: fmt.Errorf("failed to use db %s: %w", s.dbName, err),
		}
	}

	//nolint:gosec
	// sub query to fetch the all the keys that have start and end key reference, simulating range behavior.
	queryStmt := "SELECT * FROM `" + s.tableName + "` WHERE `key` >= ? AND `key` < ? order by `key`"

	// TODO Find a way to close Rows `defer resultRows.Close()`
	// unless unclosed rows and statements may cause DB connection pool exhaustion
	//nolint:sqlclosecheck
	resultRows, err := s.db.Query(queryStmt, startKey, endKey)
	if err != nil {
		return &sqlDBResultsIterator{
			err: fmt.Errorf("failed to query rows %w", err),
		}
	}

	if err = resultRows.Err(); err != nil {
		return &sqlDBResultsIterator{
			err: fmt.Errorf("failed to get resulted rows %w", err),
		}
	}

	return &sqlDBResultsIterator{
		resultRows: resultRows,
	}
}

func (i *sqlDBResultsIterator) Next() bool {
	fmt.Printf("resultRows %v\v", i.resultRows)
	return i.resultRows.Next()
}

func (i *sqlDBResultsIterator) Release() {
	if err := i.resultRows.Close(); err != nil {
		i.err = err
	}
}

func (i *sqlDBResultsIterator) Error() error {
	if i.err != nil {
		return i.err
	}

	return i.resultRows.Err()
}

// Key returns the key of the current key-value pair.
func (i *sqlDBResultsIterator) Key() []byte {
	err := i.resultRows.Scan(&i.result.key, &i.result.value)
	if err != nil {
		i.err = err
		return nil
	}

	return []byte(i.result.key)
}

// Value returns the value of the current key-value pair.
func (i *sqlDBResultsIterator) Value() []byte {
	err := i.resultRows.Scan(&i.result.key, &i.result.value)
	if err != nil {
		i.err = err
		return nil
	}

	return i.result.value
}
