/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange"
)

var logger = log.New("aries-framework/webhook")

const (
	addressPattern  = ":%s"
	connectionsPath = "/connections"
	checkTopicsPath = "/checktopics"
)

var connectionTopics = make(chan []byte, 50)

func connections(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	connMsg := didexchange.ConnectionMsg{}

	err = json.Unmarshal(msg, &connMsg)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	logger.Infof("received state transition event :: connID=%s state=%s", connMsg.ConnectionID, connMsg.State)

	connectionTopics <- msg
}

func checkTopics(w http.ResponseWriter, r *http.Request) {
	select {
	case topic := <-connectionTopics:
		_, err := w.Write(topic)
		if err != nil {
			fmt.Fprintf(w, `{"error":"failed to pull topics, cause: %s"}`, err)
		}
	case <-time.After(100 * time.Millisecond):
		fmt.Fprintf(w, `{"error":"no topic found in queue"}`)
	}
}

func main() {
	port := os.Getenv("WEBHOOK_PORT")
	if port == "" {
		panic("port to be passed as ENV variable")
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc(connectionsPath, connections).Methods(http.MethodPost)
	router.HandleFunc(checkTopicsPath, checkTopics).Methods(http.MethodGet)
	logger.Fatalf("webhook server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}
