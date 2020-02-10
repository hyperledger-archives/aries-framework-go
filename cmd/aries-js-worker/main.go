// +build js,wasm

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/controller"
	cmdctrl "github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
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
	pkgMap := defaultHandlers()

	if isTest {
		return pkgMap
	}

	commands := getAllCommands()

	for _, cmd := range commands {
		fnMap, ok := pkgMap[cmd.Name()]
		if !ok {
			fnMap = make(map[string]func(*command) *result)
		}

		fnMap[cmd.Method()] = cmdExecToFn(cmd.Handle())
		pkgMap[cmd.Name()] = fnMap
	}

	return pkgMap
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

// initAries creates aries agent instance
// TODO currently running on default opts, should be able pass custom framework opts
func getAllCommands() []cmdctrl.Handler {
	msgHandler := msghandler.NewRegistrar()

	a, err := aries.New(aries.WithMessageServiceProvider(msgHandler))
	if err != nil {
		js.Global().Get("console").Call("error",
			fmt.Sprintf("aries wasm: failed to aries framework : %s", err),
		)

		return nil
	}

	ctx, err := a.Context()
	if err != nil {
		js.Global().Get("console").Call("error",
			fmt.Sprintf("aries wasm: failed to get aries framework context: %s", err),
		)

		return nil
	}

	commands, err := controller.GetCommandHandlers(ctx, controller.WithMessageHandler(msgHandler))
	if err != nil {
		js.Global().Get("console").Call("error",
			fmt.Sprintf("aries wasm: failed to get command list: %s", err),
		)

		return nil
	}

	return commands
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

func cmdExecToFn(exec cmdctrl.Exec) func(*command) *result {
	return func(c *command) *result {
		req := bytes.NewBufferString(c.Payload)

		var buf bytes.Buffer

		err := exec(&buf, req)
		if err != nil {
			return &result{
				ID:     c.ID,
				IsErr:  true,
				ErrMsg: fmt.Sprintf("code: %+v, message: %s", err.Code(), err.Error()),
			}
		}

		return &result{
			ID:      c.ID,
			Payload: buf.String(),
		}
	}
}

func defaultHandlers() map[string]map[string]func(*command) *result {
	return map[string]map[string]func(*command) *result{
		"test": {
			"echo": func(c *command) *result {
				return &result{
					ID:      c.ID,
					Payload: "echo: ->" + c.Payload,
				}
			},
			"throwError": func(c *command) *result {
				return &result{
					ID:     c.ID,
					IsErr:  true,
					ErrMsg: "an error!",
				}
			},
			"timeout": func(c *command) *result {
				const echoTimeout = 10 * time.Second

				time.Sleep(echoTimeout)

				return &result{
					ID:      c.ID,
					Payload: "echo: ->" + c.Payload,
				}
			},
		},
	}
}
