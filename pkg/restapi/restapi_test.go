/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/stretchr/testify/require"
)

func TestNew_Failure(t *testing.T) {
	controller, err := New(&context.Provider{})
	require.Error(t, err)
	require.Equal(t, err, api.ErrSvcNotFound)
	require.Nil(t, controller)
}

func TestNew_Success(t *testing.T) {
	// TODO - remove this path manipulation after implementing #175 and #148
	path, cleanup := generateTempDir(t)
	defer cleanup()
	aries.DBPath = path

	framework, err := aries.New()
	require.NoError(t, err)
	require.NotNil(t, framework)

	defer func() {
		e := framework.Close()
		if e != nil {
			t.Fatal(e)
		}
	}()

	ctx, err := framework.Context()
	require.NoError(t, err)
	require.NotNil(t, ctx)

	controller, err := New(ctx)
	require.NoError(t, err)
	require.NotNil(t, controller)

	require.NotEmpty(t, controller.GetOperations())

}

func generateTempDir(t testing.TB) (string, func()) {
	path, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return path, func() {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}
