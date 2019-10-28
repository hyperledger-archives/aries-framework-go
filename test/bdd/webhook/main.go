/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

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
	connectionTopics <- msg
}

func checkTopics(w http.ResponseWriter, r *http.Request) {
	select {
	case topic := <-connectionTopics:
		w.Write(topic)
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
	log.Fatal(http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}
