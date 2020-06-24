/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package mysql

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	sqlStoreDBURL = "root:my-secret-pw@tcp(127.0.0.1:3306)/"
)

func TestSQLDBStore(t *testing.T) {
	t.Run("Test sql db store put and get", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		const key = "did:example:124"

		data := []byte("value")

		columns := []string{"`value`"}

		data2 := []byte(`{"key1":"value1"}`)

		did2 := "did:example:789"

		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_test ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_test (.+)").WithArgs(key, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_test (.+)").WithArgs(key).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))
		mock.ExpectExec("INSERT INTO t_test (.+)").WithArgs(key, data2, data2).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_test (.+)").WithArgs(key, data2, data2).WillReturnError(err)
		mock.ExpectQuery("SELECT (.+) FROM t_test (.+)").WithArgs(key).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data2))
		mock.ExpectQuery("SELECT (.+) FROM t_test (.+)").WithArgs(did2).WillReturnError(
			storage.ErrDataNotFound)
		mock.ExpectQuery("SELECT (.+) FROM t_test (.+)").WithArgs(did2).WillReturnError(
			fmt.Errorf("no rows"))
		mock.ExpectClose()

		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		prov.db = db

		store, err := prov.OpenStore("test")
		require.NoError(t, err)

		err = store.Put(key, data)
		require.NoError(t, err)

		doc, err := store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// test changing value of the key
		err = store.Put(key, data2)
		require.NoError(t, err)

		// testing error
		err = store.Put(key, data2)
		require.Error(t, err)

		doc, err = store.Get(key)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data2, doc)

		_, err = store.Get(did2)
		require.Error(t, err)
		require.Contains(t, storage.ErrDataNotFound.Error(), err.Error())

		// nil key
		_, err = store.Get("")
		require.Error(t, err)
		require.Equal(t, storage.ErrKeyRequired, err)

		// nil key
		err = store.Put("", data)
		require.Error(t, err)
		require.Equal(t, storage.ErrKeyRequired, err)

		_, err = store.Get(did2)
		require.Error(t, err)
		require.Contains(t, storage.ErrDataNotFound.Error(), err.Error())

		err = prov.Close()
		require.NoError(t, err)

		// we make sure that all expectations were met
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}
func TestSQLStoreMultiGetAndPut(t *testing.T) {
	t.Run("Test sql multi store put and get", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		const commonKey = "did:example:1"

		data := []byte("value")

		columns := []string{"`value`"}

		// store1
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store1 ").WillReturnResult(
			sqlmock.NewResult(1, 1))

		// store 2
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store2 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_store1 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store1 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))
		mock.ExpectQuery("SELECT (.+) FROM t_store2 (.+)").WithArgs(commonKey).WillReturnError(
			storage.ErrDataNotFound)
		mock.ExpectExec("INSERT INTO t_store2 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store2 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))
		// recreate store1
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store1 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store1 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))
		mock.ExpectQuery("SELECT (.+) FROM t_store1 (.+)").WithArgs(commonKey).WillReturnError(err)

		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		prov.db = db
		// create store 1 & store 2
		store1, err := prov.OpenStore("store1")
		require.NoError(t, err)

		store2, err := prov.OpenStore("store2")
		require.NoError(t, err)

		// put in store 1
		err = store1.Put(commonKey, data)
		require.NoError(t, err)

		// get in store 1 - found
		doc, err := store1.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// get in store 2 - not found
		doc, err = store2.Get(commonKey)
		require.Error(t, err)
		require.Equal(t, err, storage.ErrDataNotFound)
		require.Empty(t, doc)

		// put in store 2
		err = store2.Put(commonKey, data)
		require.NoError(t, err)

		// get in store 2 - found
		doc, err = store2.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// create new store 3 with same name as store1
		store3, err := prov.OpenStore("store1")
		require.NoError(t, err)

		// get in store 3 - found
		doc, err = store3.Get(commonKey)
		require.NoError(t, err)
		require.NotEmpty(t, doc)
		require.Equal(t, data, doc)

		// testing err
		doc, err = store3.Get(commonKey)
		require.Error(t, err)
		require.Empty(t, doc)

		// store length
		require.Len(t, prov.dbs, 2)

		// we make sure that all expectations were met
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}
func TestSQLStoreFailure(t *testing.T) {
	t.Run("Test sql db store failures", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		prov, err := NewProvider("")
		require.Error(t, err)
		require.Contains(t, err.Error(), blankDBPathErrMsg)
		require.Nil(t, prov)

		// Invalid db path
		_, err = NewProvider("root:@tcp(127.0.0.1:45454)")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open connection")

		// sample
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnError(
			fmt.Errorf("failed to create db %s: %w", "sample", err))

		// sample 2
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnError(
			fmt.Errorf("failed to use db %s: %w", "sample2", err))

		prov, err = NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		prov.db = db

		store, err := prov.OpenStore("sample")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create db")
		require.Nil(t, store)

		prov, err = NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		// wrong path
		prov.db = db
		store, err = prov.OpenStore("sample2")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to use db")
		require.Nil(t, store)

		// we make sure that all expectations were met
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}
func TestSQLStoreMultiStore(t *testing.T) {
	t.Run("Test sqlDB multi store close by name", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		const commonKey = "did:example:1"
		data := []byte("value")
		columns := []string{"`value`"}
		// store1
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store_1 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_store_1 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store_1 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))

		// store2
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store_2 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_store_2 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store_2 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))

		// store3
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store_3 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_store_3 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store_3 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))

		// store4
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store_4 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_store_4 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store_4 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))

		// store5
		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_store_5 ").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("INSERT INTO t_store_5 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectQuery("SELECT (.+) FROM t_store_5 (.+)").WithArgs(commonKey).WillReturnRows(
			sqlmock.NewRows(columns).AddRow(data))
		mock.ExpectClose()

		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		storeNames := []string{"store_1", "store_2", "store_3", "store_4", "store_5"}
		storesToClose := []string{"store_1", "store_3", "store_5"}

		prov.db = db

		for _, name := range storeNames {
			store, e := prov.OpenStore(name)
			require.NoError(t, e)

			e = store.Put(commonKey, data)
			require.NoError(t, e)

			dataRead, e := store.Get(commonKey)
			require.NoError(t, e)
			require.Equal(t, data, dataRead)
		}

		// verify store length
		require.Len(t, prov.dbs, 5)

		for _, name := range storesToClose {
			e := prov.CloseStore(name)
			require.NoError(t, e)
		}

		// verify store length
		require.Len(t, prov.dbs, 2)

		// try to close non existing db
		err = prov.CloseStore("store_x")
		require.NoError(t, err)

		// verify store length
		require.Len(t, prov.dbs, 2)

		err = prov.Close()
		require.NoError(t, err)

		// verify store length
		require.Empty(t, prov.dbs)

		// try close all again
		err = prov.Close()
		require.NoError(t, err)

		// we make sure that all expectations were met
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}
func TestSQLDBStoreDelete(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	const commonKey = "did:example:1234"

	data := []byte("value1")

	columns := []string{"`value`"}

	mock.ExpectBegin()
	mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
		sqlmock.NewResult(1, 1))
	mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("CREATE Table IF NOT EXISTS t_store1").WillReturnResult(
		sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO t_store1 (.+)").WithArgs(commonKey, data, data).WillReturnResult(
		sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT (.+) FROM t_store1 (.+)").WithArgs(commonKey).WillReturnRows(
		sqlmock.NewRows(columns).AddRow(data))
	mock.ExpectExec("DELETE FROM t_store1 (.+)").WithArgs(commonKey).WillReturnResult(
		sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT (.+) FROM t_store1 (.+)").WithArgs(commonKey).WillReturnError(
		storage.ErrDataNotFound)
	mock.ExpectExec("DELETE FROM t_store1 (.+)").WithArgs(commonKey).WillReturnError(err)

	prov, err := NewProvider(sqlStoreDBURL)
	require.NoError(t, err)

	prov.db = db
	// create store 1
	store1, err := prov.OpenStore("store1")
	require.NoError(t, err)

	// put in store 1
	err = store1.Put(commonKey, data)
	require.NoError(t, err)

	// get in store 1 - found
	doc, err := store1.Get(commonKey)
	require.NoError(t, err)
	require.NotEmpty(t, doc)
	require.Equal(t, data, doc)

	// now try Delete with an empty key - should fail
	err = store1.Delete("")
	require.EqualError(t, err, "key is mandatory")

	// finally test Delete an existing key
	err = store1.Delete(commonKey)
	require.NoError(t, err)

	doc, err = store1.Get(commonKey)
	require.EqualError(t, err, storage.ErrDataNotFound.Error())
	require.Empty(t, doc)

	err = store1.Delete(commonKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to delete row")

	// we make sure that all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
func TestSQLDBStoreIterator(t *testing.T) {
	t.Run("Test sql db store iterator", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
		}

		const valPrefix = "val-for-%s"

		columns := []string{"`key`", "`value`"}

		mock.ExpectBegin()
		mock.ExpectExec("CREATE DATABASE IF NOT EXISTS").WillReturnResult(
			sqlmock.NewResult(1, 1))
		mock.ExpectExec("USE ").WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectExec("CREATE Table IF NOT EXISTS t_testIterator").WillReturnResult(
			sqlmock.NewResult(1, 1))

		prov, err := NewProvider(sqlStoreDBURL)
		require.NoError(t, err)

		prov.db = db
		store, err := prov.OpenStore("testIterator")
		require.NoError(t, err)

		keys := []string{"abc_123", "abc_124", "abc_125", "abc_126", "jkl_123", "mno_123"}

		for _, key := range keys {
			mock.ExpectExec("INSERT INTO t_testIterator (.+)").WithArgs(key,
				[]byte(fmt.Sprintf(valPrefix, key)),
				[]byte(fmt.Sprintf(valPrefix, key))).WillReturnResult(sqlmock.NewResult(1, 1))
			err = store.Put(key, []byte(fmt.Sprintf(valPrefix, key)))
			require.NoError(t, err)
		}
		rowSet0 := sqlmock.NewRows(columns)
		rowSet1 := sqlmock.NewRows(columns).
			AddRow("abc_123", "val-for-abc_123").
			AddRow("abc_124", "val-for-abc_124").
			AddRow("abc_125", "val-for-abc_125").
			AddRow("abc_126", "val-for-abc_126")

		rowSet2 := sqlmock.NewRows(columns).
			AddRow("abc_123", "val-for-abc_123").
			AddRow("abc_124", "val-for-abc_124").
			AddRow("abc_125", "val-for-abc_125").
			AddRow("abc_126", "val-for-abc_126").
			AddRow("jkl_123", "val-for-jkl_123").
			AddRow("mno_123", "val-for-mno_123")

		rowSet3 := sqlmock.NewRows(columns).
			AddRow("abc_123", "val-for-abc_123").
			AddRow("abc_124", "val-for-abc_124").
			AddRow("abc_125", "val-for-abc_125").
			AddRow("abc_126", "val-for-abc_126").
			AddRow("jkl_123", "val-for-jkl_123")

		mock.ExpectQuery("SELECT (.+)").WithArgs("abc_",
			"abc_~").WillReturnRows(rowSet1)
		mock.ExpectQuery("SELECT (.+)").WithArgs("abc_",
			"mno_~").WillReturnRows(rowSet2)
		mock.ExpectQuery("SELECT (.+)").WithArgs("abc_",
			"mno_123").WillReturnRows(rowSet3)
		mock.ExpectQuery("SELECT (.+)").WithArgs("",
			"").WillReturnRows(rowSet0)

		itr := store.Iterator("abc_", "abc_"+storage.EndKeySuffix)
		require.NoError(t, itr.Error())
		verifyItr(t, itr, 4, "abc_")

		itr = store.Iterator("abc_", "mno_"+storage.EndKeySuffix)
		require.NoError(t, itr.Error())
		verifyItr(t, itr, 6, "")

		itr = store.Iterator("abc_", "mno_123")
		require.NoError(t, itr.Error())
		verifyItr(t, itr, 5, "")

		itr = store.Iterator("", "")
		require.NoError(t, itr.Error())
		verifyItr(t, itr, 0, "")

		itr = store.Iterator("abc", "mno_123")
		require.Error(t, itr.Error())
		require.Contains(t, itr.Error().Error(), "failed to query rows")

		// we make sure that all expectations were met
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}

func verifyItr(t *testing.T, itr storage.StoreIterator, count int, prefix string) {
	var vals []string

	for itr.Next() {
		if prefix != "" {
			require.True(t, strings.HasPrefix(string(itr.Key()), prefix))
		}

		vals = append(vals, string(itr.Value()))
	}

	require.Len(t, vals, count)

	itr.Release()
	require.False(t, itr.Next())
	require.Empty(t, itr.Key())
	require.Empty(t, itr.Value())
	require.Error(t, itr.Error())
	require.Contains(t, itr.Error().Error(), "sql: Rows are closed")
}
