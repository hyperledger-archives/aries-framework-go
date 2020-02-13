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

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller"
	cmdctrl "github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/messaging/msghandler"
	arieshttp "github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/http"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/ws"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

const (
	handleResultFn  = "handleResult"
	ariesCommandPkg = "aries"
	ariesStartFn    = "Start"
	ariesStopFn     = "Stop"
)

var logger = log.New("aries-js-worker")

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
	LogLevel             string   `json:"log-level"`
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
			logger.Errorf("aries wasm: unable to unmarshal input=%s. err=%s", args[0].String(), err)

			return nil
		}
		in <- cmd

		return nil
	}
}

func pipe(input chan *command, output chan *result) {
	handlers := testHandlers()

	addAriesHandlers(handlers)

	for c := range input {
		if c.ID == "" {
			logger.Warnf("aries wasm: missing ID for input: %v", c)
		}

		if pkg, found := handlers[c.Pkg]; found {
			if fn, found := pkg[c.Fn]; found {
				output <- fn(c)
				continue
			}
		}

		output <- handlerNotFoundErr(c)
	}
}

func sendTo(out chan *result) {
	for r := range out {
		out, err := json.Marshal(r)
		if err != nil {
			logger.Errorf("aries wasm: failed to marshal response for id=%s err=%s ", r.ID, err)
		}

		js.Global().Call(handleResultFn, string(out))
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

		if len(buf.Bytes()) > 0 {
			if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
				return &result{
					ID:    c.ID,
					IsErr: true,
					ErrMsg: fmt.Sprintf(
						"aries wasm: failed to unmarshal command result=%+v err=%s",
						buf.String(), err),
				}
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

func isStartCommand(c *command) bool {
	return c.Pkg == ariesCommandPkg && c.Fn == ariesStartFn
}

func isStopCommand(c *command) bool {
	return c.Pkg == ariesCommandPkg && c.Fn == ariesStopFn
}

func handlerNotFoundErr(c *command) *result {
	if isStartCommand(c) {
		return newErrResult(c.ID, "Aries agent already started")
	} else if isStopCommand(c) {
		return newErrResult(c.ID, "Aries agent not running")
	}

	return newErrResult(c.ID, fmt.Sprintf("invalid pkg/fn: %s/%s, make sure aries is started", c.Pkg, c.Fn))
}

func addAriesHandlers(pkgMap map[string]map[string]func(*command) *result) {
	fnMap := make(map[string]func(*command) *result)
	fnMap[ariesStartFn] = func(c *command) *result {
		cOpts, err := startOpts(c.Payload)
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		err = setLogLevel(cOpts.LogLevel)
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		options, err := ariesOpts(cOpts)
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		msgHandler := msghandler.NewRegistrar()
		options = append(options, aries.WithMessageServiceProvider(msgHandler))

		a, err := aries.New(options...)
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		ctx, err := a.Context()
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		commands, err := controller.GetCommandHandlers(ctx, controller.WithMessageHandler(msgHandler),
			controller.WithDefaultLabel(cOpts.Label), controller.WithNotifier(&jsNotifier{}))
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		// add command handlers
		addCommandHandlers(commands, pkgMap)

		// add stop aries handler
		addStopAriesHandler(a, pkgMap)

		return &result{
			ID:      c.ID,
			Payload: map[string]interface{}{"message": "aries agent started successfully"},
		}
	}

	pkgMap[ariesCommandPkg] = fnMap
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
	fnMap[ariesStopFn] = func(c *command) *result {
		err := a.Close()
		if err != nil {
			return newErrResult(c.ID, err.Error())
		}

		// reset handlers when stopped
		for k := range pkgMap {
			delete(pkgMap, k)
		}

		// put back start command once stopped
		addAriesHandlers(pkgMap)

		return &result{
			ID:      c.ID,
			Payload: map[string]interface{}{"message": "aries agent stopped"},
		}
	}
	pkgMap[ariesCommandPkg] = fnMap
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

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "json",
		Result:  opts,
	})
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(payload)
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

func setLogLevel(logLevel string) error {
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			return err
		}

		log.SetLevel("", level)
		logger.Infof("log level set to `%s`", logLevel)
	}

	return nil
}

// jsNotifier notifies about all incoming events
type jsNotifier struct {
}

// Notify is mock implementation of webhook notifier Notify()
func (n *jsNotifier) Notify(topic string, message []byte) error {
	payload := make(map[string]interface{})
	if err := json.Unmarshal(message, &payload); err != nil {
		return err
	}

	out, err := json.Marshal(&result{
		ID:      uuid.New().String(),
		Topic:   topic,
		Payload: payload,
	})

	if err != nil {
		return err
	}

	js.Global().Call(handleResultFn, string(out))

	return nil
}
