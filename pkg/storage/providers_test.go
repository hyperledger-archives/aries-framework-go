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
	"path/filepath"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	drivermysql "github.com/go-sql-driver/mysql"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	couchdbstore "github.com/hyperledger/aries-framework-go/pkg/storage/couchdb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mysql"
)

const (
	couchDBURL          = "admin:password@127.0.0.1:5983"
	dockerCouchdbImage  = "couchdb"
	dockerCouchdbTag    = "3.1.0"
	dockerCouchdbVolume = "%s/scripts/couchdb-config/10-single-node.ini:/opt/couchdb/etc/local.d/10-single-node.ini"

	sqlStoreDBURL    = "root:my-secret-pw@tcp(127.0.0.1:3300)/"
	dockerMySQLImage = "mysql"
	dockerMySQLTag   = "8.0.20"
)

var logger = log.New("aries-framework/storage/test")

type mysqlLogger struct{}

func (*mysqlLogger) Print(v ...interface{}) {
	logger.Debugf(fmt.Sprint(v...))
}

func TestMain(m *testing.M) {
	code := 1

	defer func() { os.Exit(code) }()

	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("pool: %v", err))
	}

	mysqlResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMySQLImage, Tag: dockerMySQLTag, Env: []string{"MYSQL_ROOT_PASSWORD=my-secret-pw"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"3306/tcp": {{HostIP: "", HostPort: "3300"}},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err = pool.Purge(mysqlResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	path, err := filepath.Abs("./../../")
	if err != nil {
		panic(fmt.Sprintf("filepath: %v", err))
	}

	couchdbResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerCouchdbImage,
		Tag:        dockerCouchdbTag,
		Env:        []string{"COUCHDB_USER=admin", "COUCHDB_PASSWORD=password"},
		Mounts:     []string{fmt.Sprintf(dockerCouchdbVolume, path)},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5984/tcp": {{HostIP: "", HostPort: "5983"}},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("run with options: %v", err))
	}

	defer func() {
		if err := pool.Purge(couchdbResource); err != nil {
			panic(fmt.Sprintf("purge: %v", err))
		}
	}()

	if err := checkCouchDB(); err != nil {
		panic(fmt.Sprintf("check CouchDB: %v", err))
	}

	if err := checkMySQL(); err != nil {
		panic(fmt.Sprintf("check MySQL: %v", err))
	}

	code = m.Run()
}

const retries = 60

func checkCouchDB() error {
	return backoff.Retry(func() error {
		return couchdbstore.PingCouchDB(couchDBURL)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
}

func checkMySQL() error {
	if err := drivermysql.SetLogger((*mysqlLogger)(nil)); err != nil {
		return fmt.Errorf("set logger: %w", err)
	}

	return backoff.Retry(func() error {
		db, err := sql.Open("mysql", sqlStoreDBURL)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}

		return db.Ping()
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), retries))
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
