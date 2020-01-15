/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"
)

// TODO Signal JS when WASM is loaded and ready.
//      This is being used in tests for now.
var ready = make(chan struct{}) //nolint:gochecknoglobals
var isTest = false              //nolint:gochecknoglobals

// command is received from JS
type command struct {
	ID      string `json:"id"`
	Pkg     string `json:"pkg"`
	Fn      string `json:"fn"`
	Payload string `json:"payload"`
}

// result is sent back to JS
type result struct {
	ID      string `json:"id"`
	IsErr   bool   `json:"isErr"`
	ErrMsg  string `json:"errMsg"`
	Payload string `json:"payload"`
}

// All supported command handlers.
func handlers() map[string]map[string]func(*command) *result {
	return map[string]map[string]func(*command) *result{
		"test": {
			"echo":       echo,
			"throwError": throwError,
			"timeout":    timeout,
		},
	}
}

// main registers the 'handleMsg' function in the JS context's global scope to receive commands.
// results are posted back to the 'handleResult' JS function.
func main() {
	input := make(chan *command)
	output := make(chan *result)

	go pipe(input, output)

	go sendTo(output)

	js.Global().Set("handleMsg", js.FuncOf(takeFrom(input)))

	if isTest {
		ready <- struct{}{}
	}

	select {}
}

func takeFrom(in chan *command) func(js.Value, []js.Value) interface{} {
	return func(_ js.Value, args []js.Value) interface{} {
		cmd := &command{}
		if err := json.Unmarshal([]byte(args[0].String()), cmd); err != nil {
			js.Global().Get("console").Call(
				"log",
				fmt.Sprintf("aries wasm: unable to unmarshal input=%s. err=%s", args[0].String(), err),
			)
		}
		in <- cmd
		return nil
	}
}

func pipe(input chan *command, output chan *result) {
	handlers := handlers()

	for c := range input {
		if c.ID == "" {
			js.Global().Get("console").Call(
				"log",
				fmt.Sprintf("aries wasm: missing ID for input: %v", c),
			)
		}

		if pkg, found := handlers[c.Pkg]; found {
			if fn, found := pkg[c.Fn]; found {
				output <- fn(c)
			} else {
				output <- &result{
					ID:     c.ID,
					IsErr:  true,
					ErrMsg: "invalid fn: " + c.Fn,
				}
			}
		} else {
			output <- &result{
				ID:     c.ID,
				IsErr:  true,
				ErrMsg: "invalid pkg: " + c.Pkg,
			}
		}
	}
}

func sendTo(out chan *result) {
	for r := range out {
		out, err := json.Marshal(r)
		if err != nil {
			js.Global().Get("console").Call(
				"log",
				fmt.Sprintf("aries wasm: failed to marshal response for id=%s err=%s ", r.ID, err),
			)
		}

		js.Global().Call("handleResult", string(out))
	}
}

// test handler
func echo(c *command) *result {
	return &result{
		ID:      c.ID,
		Payload: "echo: " + c.Payload,
	}
}

// test handler
func throwError(c *command) *result {
	return &result{
		ID:     c.ID,
		IsErr:  true,
		ErrMsg: "an error!",
	}
}

// test handler
func timeout(c *command) *result {
	time.Sleep(10 * time.Second)
	return echo(c)
}
