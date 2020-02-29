/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("aries-framework/webhook")

const (
	addressPattern  = ":%s"
	checkTopicsPath = "/checktopics"
	topicsSize      = 5000
	topicTimeout    = 100 * time.Millisecond
)

var topics = make(chan []byte, topicsSize) //nolint:gochecknoglobals

func receiveTopics(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	logger.Infof("received topic message: %s", string(msg))

	topics <- msg
}

func checkTopics(w http.ResponseWriter, r *http.Request) {
	select {
	case topic := <-topics:
		_, err := w.Write(topic)
		if err != nil {
			fmt.Fprintf(w, `{"error":"failed to pull topics, cause: %s"}`, err)
		}
	case <-time.After(topicTimeout):
		fmt.Fprintf(w, `{"error":"no topic found in queue"}`)
	}
}

func main() {
	port := os.Getenv("WEBHOOK_PORT")
	if port == "" {
		panic("port to be passed as ENV variable")
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", receiveTopics).Methods(http.MethodPost)
	router.HandleFunc(checkTopicsPath, checkTopics).Methods(http.MethodGet)
	logger.Fatalf("webhook server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}
