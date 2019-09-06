/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package support

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewHTTPHandler(t *testing.T) {

	path := "/sample-path"
	method := "GET"
	handled := make(chan bool)
	handlerFn := func(w http.ResponseWriter, r *http.Request) {
		// do nothing
		handled <- true
	}

	handler := NewHTTPHandler(path, method, handlerFn)
	require.Equal(t, path, handler.Path())
	require.Equal(t, method, handler.Method())
	require.NotNil(t, handler.Handle())

	go handler.Handle()(nil, nil)

	select {
	case res := <-handled:
		require.True(t, res)
	case <-time.After(2 * time.Second):
		t.Fatal("handler function didnt get executed")
	}
}
