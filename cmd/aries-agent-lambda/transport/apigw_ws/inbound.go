/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package apigw_ws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	//"github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
)

var (
	transportProvider transport.Provider
)

type Inbound struct {
	externalAddr string
}

// UnpackMessage using 'pack' with a 'source' of either 'ws' or 'http'.
func UnpackMessage(message []byte, pack transport.Packager, source string) (*transport.Envelope, error) {
	doubleQuote := []byte("\"")
	msg := message

	if bytes.HasPrefix(message, doubleQuote) && bytes.HasSuffix(message, doubleQuote) {
		log.Printf("unpack msg from %s is wrapped with double quotes trying to base64 decode before unpacking..",
			source)

		msg = msg[1 : len(msg)-1]

		var decodedMsg []byte

		decodedMsg1, err1 := base64.URLEncoding.DecodeString(string(msg))
		decodedMsg2, err2 := base64.RawURLEncoding.DecodeString(string(msg))

		switch {
		case err1 == nil:
			decodedMsg = decodedMsg1
		case err2 == nil:
			decodedMsg = decodedMsg2
		default:
			return nil, fmt.Errorf("not base64 encoded message error from %s: URLEncoding error: %w, RawURLEncoding"+
				" error: %v", source, err1, err2)
		}

		msg = decodedMsg
	}

	unpackMsg, err := pack.UnpackMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack msg from %s: %w", source, err)
	}

	return unpackMsg, nil
}

func NewInboundHandler() http.HandlerFunc {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processWSRequest(w, r, transportProvider)
	})

	return handler
}

func processWSRequest(w http.ResponseWriter, r *http.Request, prov transport.Provider) {
	log.Printf("Processing WS request: %+v", r)
	connectionId := r.Header.Get("X-ConnectionId")
	log.Printf("Connection ID: %s", connectionId)
	switch r.Method {
	case "PUT":
		{
			// TODO: Websocket connected, save a reference to it in the DB
			log.Printf(">>>>> Connect Event")
			w.WriteHeader(http.StatusOK)
		}
	case "POST":
		{

			log.Printf(">>>>> WS Message Event")

			message, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Fatalf("read body failed : %v", err)
				return
			}

			unpackMsg, err := UnpackMessage(message, transportProvider.Packager(), "ws")
			if err != nil {
				log.Fatalf("unpack message failed : %v", err)
				return
			}

			trans := &decorator.Transport{}
			err = json.Unmarshal(unpackMsg.Message, trans)
			if err != nil {
				log.Fatalf("unmarshal transport decorator : %v", err)
				return
			}

			respChannel := make(chan []byte)
			getConnPool().addKey(unpackMsg, trans, connectionId, respChannel)

			err = prov.InboundMessageHandler()(unpackMsg)
			if err != nil {
				log.Fatalf("incoming msg processing failed: %v", err)
				return
			}

			select {
			//case response := <-respChannel:
			//	w.WriteHeader(http.StatusOK)
			//	log.Printf(">>>>>>>>> Got response\n")
			//	w.Write(response)
			case <-time.After(5 * time.Second):
				log.Printf(">>>>>>>>> No response within 5 secs\n")
				w.WriteHeader(http.StatusNoContent)
			}
		}
	case "DELETE":
		{
			// TODO: Websocket was disconnected, clean up references
			log.Printf(">>>>> WS Disconnect Event")
			w.WriteHeader(http.StatusOK)
		}
	default:
		log.Printf("Unknown Event")
	}

}

func WithInboundWS(externalAddr string) aries.Option {
	return func(opts *aries.Aries) error {
		transport, _ := NewInbound(externalAddr)
		return aries.WithInboundTransport(transport)(opts)
	}
}

func NewInbound(externalAddr string) (*Inbound, error) {
	if externalAddr == "" {
		return nil, errors.New("external addr is mandatory")
	}
	return &Inbound{
		externalAddr: externalAddr,
	}, nil
}

func (i *Inbound) Start(prov transport.Provider) error {
	transportProvider = prov

	return nil
}

func (i *Inbound) Stop() error {
	return nil
}

func (i *Inbound) Endpoint() string {
	return i.externalAddr
}
