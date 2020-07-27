// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall/js"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// test callbacks.
var callbacks = make(map[string]chan *result) // nolint:gochecknoglobals

func TestMain(m *testing.M) {
	isTest = true

	go main()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		panic(errors.New("go main() timed out"))
	}

	results := make(chan *result)

	js.Global().Set("handleResult", js.FuncOf(acceptResults(results)))

	go dispatchResults(results)
	os.Exit(m.Run())
}

func TestEchoCmd(t *testing.T) {
	echo := newCommand("test", "echo", map[string]interface{}{"id": uuid.New().String()})
	result := make(chan *result)

	callbacks[echo.ID] = result
	defer delete(callbacks, echo.ID)

	js.Global().Call("handleMsg", toString(echo))

	select {
	case r := <-result:
		assert.Equal(t, echo.ID, r.ID)
		assert.False(t, r.IsErr)
		assert.Empty(t, r.ErrMsg)
		assert.Equal(t, r.Payload["echo"], echo.Payload)
	case <-time.After(5 * time.Second):
		t.Error("test timeout")
	}
}

func TestErrorCmd(t *testing.T) {
	errCmd := newCommand("test", "throwError", map[string]interface{}{})
	result := make(chan *result)
	callbacks[errCmd.ID] = result

	defer delete(callbacks, errCmd.ID)

	js.Global().Call("handleMsg", toString(errCmd))

	select {
	case r := <-result:
		assert.Equal(t, errCmd.ID, r.ID)
		assert.True(t, r.IsErr)
		assert.NotEmpty(t, r.ErrMsg)
		assert.Empty(t, r.Payload)
	case <-time.After(5 * time.Second):
		t.Error("test timeout")
	}
}

func acceptResults(in chan *result) func(js.Value, []js.Value) interface{} {
	return func(_ js.Value, args []js.Value) interface{} {
		r := &result{}
		if err := json.Unmarshal([]byte(args[0].String()), r); err != nil {
			panic(err)
		}
		in <- r

		return nil
	}
}

func dispatchResults(in chan *result) {
	for r := range in {
		cb, found := callbacks[r.ID]
		if !found {
			panic(fmt.Errorf("callback with ID %s not found", r.ID))
		}
		cb <- r
	}
}

func newCommand(pkg, fn string, payload map[string]interface{}) *command {
	return &command{
		ID:      uuid.New().String(),
		Pkg:     pkg,
		Fn:      fn,
		Payload: payload,
	}
}

func toString(c *command) string {
	s, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Errorf("failed to marshal: %+v", c))
	}

	return string(s)
}
