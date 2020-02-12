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
	"net/http"
	"syscall/js"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/controller"
	cmdctrl "github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/webhook"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

// TODO Signal JS when WASM is loaded and ready.
//      This is being used in tests for now.
var ready = make(chan struct{}) //nolint:gochecknoglobals
var isTest = false              //nolint:gochecknoglobals

// command is received from JS
type command struct {
	ID      string                 `json:"id"`
	Pkg     string                 `json:"pkg"`
	Fn      string                 `json:"fn"`
	Payload map[string]interface{} `json:"payload"`
}

// result is sent back to JS
type result struct {
	ID      string                 `json:"id"`
	IsErr   bool                   `json:"isErr"`
	ErrMsg  string                 `json:"errMsg"`
	Payload map[string]interface{} `json:"payload"`
	Topic   string                 `json:"topic"`
}

// ariesStartOpts contains opts for starting aries
type ariesStartOpts struct {
	Label                string   `json:"agent-default-label"`
	HTTPResolver         string   `json:"http-resolver-url"`
	AutoAccept           bool     `json:"auto-accept"`
	OutboundTransport    []string `json:"outbound-transport"`
	TransportReturnRoute string   `json:"transport-return-route"`
	Notifier             string   `json:"notifier-func-name"`
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

			return nil
		}
		in <- cmd

		return nil
	}
}

func pipe(input chan *command, output chan *result) {
	handlers := testHandlers()

	var started bool

	if isTest {
		started = true
	}

	for c := range input {
		if c.ID == "" {
			js.Global().Get("console").Call(
				"log",
				fmt.Sprintf("aries wasm: missing ID for input: %v", c),
			)
		}

		if !started {
			var rs *result
			rs, started = startAries(c, handlers)
			output <- rs

			continue
		}

		if pkg, found := handlers[c.Pkg]; found {
			if fn, found := pkg[c.Fn]; found {
				output <- fn(c)
				// support restart by resetting flag
				if c.Pkg == "aries" && c.Fn == "Stop" {
					started = false
				}
			} else {
				output <- newErrResult(c.ID, "invalid fn: "+c.Pkg)
			}
		} else {
			output <- newErrResult(c.ID, "invalid pkg: "+c.Pkg)
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
		b, er := json.Marshal(c.Payload)
		if er != nil {
			return &result{
				ID:     c.ID,
				IsErr:  true,
				ErrMsg: fmt.Sprintf("aries wasm: failed to unmarshal payload. err=%s", er),
			}
		}

		req := bytes.NewBuffer(b)

		var buf bytes.Buffer

		err := exec(&buf, req)
		if err != nil {
			return newErrResult(c.ID, fmt.Sprintf("code: %+v, message: %s", err.Code(), err.Error()))
		}

		payload := make(map[string]interface{})
		if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
			return &result{
				ID:    c.ID,
				IsErr: true,
				ErrMsg: fmt.Sprintf(
					"aries wasm: failed to unmarshal command result=%+v err=%s",
					buf.String(), err),
			}
		}

		return &result{
			ID:      c.ID,
			Payload: payload,
		}
	}
}

func testHandlers() map[string]map[string]func(*command) *result {
	return map[string]map[string]func(*command) *result{
		"test": {
			"echo": func(c *command) *result {
				return &result{
					ID:      c.ID,
					Payload: map[string]interface{}{"echo": c.Payload},
				}
			},
			"throwError": func(c *command) *result {
				return newErrResult(c.ID, "an error !!")
			},
			"timeout": func(c *command) *result {
				const echoTimeout = 10 * time.Second

				time.Sleep(echoTimeout)

				return &result{
					ID:      c.ID,
					Payload: map[string]interface{}{"echo": c.Payload},
				}
			},
		},
	}
}

func startAries(c *command, pkgMap map[string]map[string]func(*command) *result) (*result, bool) {
	if c.Pkg != "aries" && c.Fn != "Start" {
		return newErrResult(c.ID, "start aries before running any command"), false
	} else if c.Fn == "Stop" {
		return newErrResult(c.ID, "stop already called, start again to run any command"), false
	}

	cOpts, err := startOpts(c.Payload)
	if err != nil {
		return newErrResult(c.ID, err.Error()), false
	}

	options, err := ariesOpts(cOpts)
	if err != nil {
		return newErrResult(c.ID, err.Error()), false
	}

	msgHandler := msghandler.NewRegistrar()
	options = append(options, aries.WithMessageServiceProvider(msgHandler))

	a, err := aries.New(options...)
	if err != nil {
		return newErrResult(c.ID, err.Error()), false
	}

	ctx, err := a.Context()
	if err != nil {
		return newErrResult(c.ID, err.Error()), false
	}

	var notifier webhook.Notifier
	if cOpts.Notifier != "" {
		notifier = &jsNotifier{topic: cOpts.Notifier}
	}

	commands, err := controller.GetCommandHandlers(ctx, controller.WithMessageHandler(msgHandler),
		controller.WithDefaultLabel(cOpts.Label), controller.WithNotifier(notifier))
	if err != nil {
		return newErrResult(c.ID, err.Error()), false
	}

	// add command handlers
	addCommandHandlers(commands, pkgMap)

	// add stop aries handler
	addStopAriesHandler(a, pkgMap)

	return &result{
		ID:      c.ID,
		Payload: map[string]interface{}{"msg": "aries started"},
	}, true
}

func addCommandHandlers(commands []cmdctrl.Handler, pkgMap map[string]map[string]func(*command) *result) {
	for _, cmd := range commands {
		fnMap, ok := pkgMap[cmd.Name()]
		if !ok {
			fnMap = make(map[string]func(*command) *result)
		}

		fnMap[cmd.Method()] = cmdExecToFn(cmd.Handle())
		pkgMap[cmd.Name()] = fnMap
	}
}

func addStopAriesHandler(a *aries.Aries, pkgMap map[string]map[string]func(*command) *result) {
	fnMap := make(map[string]func(*command) *result)
	fnMap["Stop"] = func(c *command) *result {
		err := a.Close()
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		// reset handlers when stopped
		for k := range pkgMap {
			delete(pkgMap, k)
		}

		return &result{
			ID:      c.ID,
			Payload: map[string]interface{}{"msg": "aries stoppped"},
		}
	}
	pkgMap["aries"] = fnMap
}

func newErrResult(id, msg string) *result {
	return &result{
		ID:     id,
		IsErr:  true,
		ErrMsg: msg,
	}
}

func startOpts(payload map[string]interface{}) (*ariesStartOpts, error) {
	opts := &ariesStartOpts{}

	err := mapstructure.Decode(payload, opts)
	if err != nil {
		return nil, err
	}

	return opts, nil
}

func ariesOpts(opts *ariesStartOpts) ([]aries.Option, error) {
	msgHandler := msghandler.NewRegistrar()

	var options []aries.Option
	options = append(options, aries.WithMessageServiceProvider(msgHandler))

	if opts.TransportReturnRoute != "" {
		options = append(options, aries.WithTransportReturnRoute(opts.TransportReturnRoute))
	}

	for _, transport := range opts.OutboundTransport {
		switch transport {
		case "http":
			outbound, err := arieshttp.NewOutbound(arieshttp.WithOutboundHTTPClient(&http.Client{}))
			if err != nil {
				return nil, err
			}

			options = append(options, aries.WithOutboundTransports(outbound))
		case "ws":
			options = append(options, aries.WithOutboundTransports(ws.NewOutbound()))
		default:
			return nil, fmt.Errorf("unsupported transport : %s", transport)
		}
	}

	return options, nil
}

// jsNotifier notifies incoming events once registered
type jsNotifier struct {
	topic string
}

// Notify is mock implementation of webhook notifier Notify()
func (n *jsNotifier) Notify(topic string, message []byte) error {
	out, err := json.Marshal(&result{
		ID:      uuid.New().String(),
		Topic:   n.topic,
		Payload: map[string]interface{}{"notification": string(message)},
	})

	if err != nil {
		return err
	}

	js.Global().Call("handleResult", string(out))

	return nil
}
