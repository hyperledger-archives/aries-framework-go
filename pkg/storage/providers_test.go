// +build !js,!wasm,!ISSUE2183

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage_test

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	couchdbstore "github.com/hyperledger/aries-framework-go/pkg/storage/couchdb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mysql"
)

const (
	couchDBURL    = "admin:password@localhost:5984"
	sqlStoreDBURL = "root:my-secret-pw@tcp(127.0.0.1:3306)/"
)

func TestMain(m *testing.M) {
	err := couchdbstore.PingCouchDB(couchDBURL)
	if err != nil {
		fmt.Printf(err.Error() + ". Make sure CouchDB is running.\n")
		os.Exit(1)
	}

	err = checkMySQL()
	if err != nil {
		fmt.Printf(err.Error() + ". Make sure MySQL is running.\n")
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func checkMySQL() error {
	db, err := sql.Open("mysql", sqlStoreDBURL)
	if err != nil {
		return err
	}

	return db.Ping()
}

func setUpProviders(t *testing.T) []Provider {
	t.Helper()

	var providers []Provider

	couchDB, err := couchdbstore.NewProvider(
		couchDBURL, couchdbstore.WithDBPrefix("db_prefix"),
	)
	require.NoError(t, err)

	providers = append(providers,
		Provider{Provider: couchDB, Name: "CouchDB with prefix"},
		Provider{Provider: mem.NewProvider(), Name: "Mem"},
	)

	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}

	t.Cleanup(func() {
		err = os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	})

	providers = append(providers, Provider{
		Provider: leveldb.NewProvider(dbPath), Name: "LevelDB",
	})

	mysqlProvider, err := mysql.NewProvider(sqlStoreDBURL, mysql.WithDBPrefix("db_prefix"))
	require.NoError(t, err)

	providers = append(providers, Provider{
		Provider: mysqlProvider, Name: "MySql with prefix",
	})

	return providers
}
