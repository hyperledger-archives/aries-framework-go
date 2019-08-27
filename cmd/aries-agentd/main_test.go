/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testURL = "localhost:8080"

func TestStartAriesD(t *testing.T) {

	prev := os.Getenv(agentHostEnvKey)
	defer func() {
		err := os.Setenv(agentHostEnvKey, prev)
		if err != nil {
			t.Fatal(err)
		}
	}()

	err := os.Setenv(agentHostEnvKey, testURL)
	if err != nil {
		t.Fatal(err)
	}

	go main()

	newreq := func(method, url string, body io.Reader) *http.Request {
		r, err := http.NewRequest(method, url, body)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	tests := []struct {
		name string
		r    *http.Request
	}{
		{name: "1: testing get", r: newreq("GET", fmt.Sprintf("http://%s/create-invitation", testURL), nil)},
	}

	//give some time for server to start
	//TODO instead of sleep, listen for port
	time.Sleep(100 * time.Millisecond)

	for _, tt := range tests {

		resp, err := http.DefaultClient.Do(tt.r)
		if err != nil {
			t.Fatal(err)
		}

		defer func() {
			e := resp.Body.Close()
			if e != nil {
				panic(err)
			}
		}()

		require.Equal(t, resp.Status, "200 OK")
		require.NotEmpty(t, resp.Body)
		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		require.NotEmpty(t, response)
		require.True(t, isJSON(response))
	}

}

//isJSON() checks if response is json
func isJSON(res []byte) bool {
	var js map[string]interface{}
	return json.Unmarshal(res, &js) == nil

}

func TestStartAriesDWithoutHost(t *testing.T) {

	prev := os.Getenv(agentHostEnvKey)
	defer func() {
		err := os.Setenv(agentHostEnvKey, prev)
		if err != nil {
			t.Fatal(err)
		}
	}()

	err := os.Setenv(agentHostEnvKey, "")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool)

	go func() {
		main()
		done <- true
	}()

	select {
	case res := <-done:
		require.True(t, res)
	case <-time.After(5 * time.Second):
		t.Fatal("agent should fail to start when host address not provided")
	}

}
