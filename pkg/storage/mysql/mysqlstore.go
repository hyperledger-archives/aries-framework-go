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

// Provider represents an MySQL DB implementation of the storage.Provider interface
type Provider struct {
	dbURL string
	db    *sql.DB
	dbs   map[string]*sqlDBStore
	sync.RWMutex
}

type sqlDBStore struct {
	db        *sql.DB
	tableName string
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
	createDBQuery             = "CREATE DATABASE IF NOT EXISTS "
	useDBQuery                = "USE "
)

// NewProvider instantiates Provider
func NewProvider(dbPath string) (*Provider, error) {
	if dbPath == "" {
		return nil, errors.New(blankDBPathErrMsg)
	}

	// Example DB Path root:my-secret-pw@tcp(127.0.0.1:3306)/
	db, err := sql.Open("mysql", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}

	p := &Provider{
		dbURL: dbPath,
		db:    db,
		dbs:   map[string]*sqlDBStore{}}

	return p, nil
}

// OpenStore opens and returns new db for given name space.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	p.Lock()
	defer p.Unlock()

	tx, err := p.db.Begin()
	if err != nil {
		return nil, err
	}

	// creating the database
	_, err = tx.Exec(createDBQuery + name)
	if err != nil {
		return nil, fmt.Errorf("failed to create db %s: %w", name, err)
	}

	// Use is used to select the created database without this DDL operations are not permitted
	_, err = tx.Exec(useDBQuery + name)
	if err != nil {
		return nil, fmt.Errorf("failed to use db %s: %w", name, err)
	}

	tableName := tablePrefix + name
	// TODO: Issue-1940 Store the hashed key to control the width of the key varchar column
	createTableStmt := "CREATE Table IF NOT EXISTS " + tableName +
		"(`key` varchar(255) NOT NULL ,`value` BLOB, PRIMARY KEY (`key`));"

	// creating key-value table inside the database
	_, err = tx.Exec(createTableStmt)
	if err != nil {
		return nil, fmt.Errorf("failed to create table %s: %w", tableName, err)
	}

	store := &sqlDBStore{
		db:        p.db,
		tableName: tableName}

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

// CloseStore closes a previously opened store
func (p *Provider) CloseStore(name string) error {
	p.Lock()
	defer p.Unlock()

	store, exists := p.dbs[name]
	if !exists {
		return nil
	}

	delete(p.dbs, name)

	return store.db.Close()
}

// Put stores the key and the record
func (s *sqlDBStore) Put(k string, v []byte) error {
	if k == "" {
		return storage.ErrKeyRequired
	}

	// create upsert query to insert the record, checking whether the key is already mapped to a value in the store.
	createStmt := "INSERT INTO ? VALUES (?, ?) ON DUPLICATE KEY UPDATE value=?"
	// executing the prepared insert statement
	_, err := s.db.Exec(createStmt, s.tableName, k, v, v)
	if err != nil {
		return fmt.Errorf("failed to insert key and value record into %s %w ", s.tableName, err)
	}

	return nil
}

// Get fetches the record based on key
func (s *sqlDBStore) Get(k string) ([]byte, error) {
	if k == "" {
		return nil, storage.ErrKeyRequired
	}

	var value []byte
	// select query to fetch the record by key
	err := s.db.QueryRow("SELECT `value` FROM ? WHERE `key` = ?", s.tableName, k).Scan(&value)
	if err != nil {
		if strings.Contains(err.Error(), sqlDBNotFound) {
			return nil, storage.ErrDataNotFound
		}

		return nil, err
	}

	return value, nil
}

// Delete will delete record with k key
func (s *sqlDBStore) Delete(k string) error {
	if k == "" {
		return storage.ErrKeyRequired
	}
	// delete query to delete the record by key
	_, err := s.db.Exec("DELETE FROM ? WHERE `key`= ?", s.tableName, k)

	if err != nil {
		return fmt.Errorf("failed to delete row %w", err)
	}

	return nil
}

type sqlDBResultsIterator struct {
	store      *sqlDBStore
	resultRows *sql.Rows
	err        error
}

func (s *sqlDBStore) Iterator(startKey, endKey string) storage.StoreIterator {
	endKey = strings.ReplaceAll(endKey, storage.EndKeySuffix, "~")
	// sub query to fetch the all the keys that have start and end key reference, simulating range behavior.
	queryStmt := "SELECT * FROM ? WHERE `key` >= ?  AND `key` < ? order by `key`"

	resultRows, err := s.db.Query(queryStmt, s.tableName, startKey, endKey)
	if err != nil && resultRows == nil {
		return &sqlDBResultsIterator{store: s,
			err: fmt.Errorf("failed to query rows %w", err)}
	} else if err = resultRows.Err(); err != nil {
		return &sqlDBResultsIterator{store: s,
			err: fmt.Errorf("failed to get resulted rows %w", err)}
	}

	return &sqlDBResultsIterator{store: s, resultRows: resultRows}
}

func (i *sqlDBResultsIterator) Next() bool {
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
	var res result

	err := i.resultRows.Scan(&res.key, &res.value)
	if err != nil {
		i.err = err
		return nil
	}

	return []byte(res.key)
}

// Value returns the value of the current key-value pair.
func (i *sqlDBResultsIterator) Value() []byte {
	var kv result

	err := i.resultRows.Scan(&kv.key, &kv.value)
	if err != nil {
		i.err = err
		return nil
	}

	return kv.value
}
