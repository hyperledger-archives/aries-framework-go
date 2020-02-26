/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

var logger = log.New("aries-framework/webhook")

const (
	addressPattern  = ":%s"
	pushTopic       = "/{topic}"
	checkTopicsPath = "/checktopics"
	topicsSize      = 50
	topicTimeout    = 100 * time.Millisecond
	wsRate          = 100 * time.Millisecond
	wsBurst         = 10
	wsCtxTimeout    = 10 * time.Second
)

var topics = make(chan []byte, topicsSize) //nolint:gochecknoglobals

func receiveTopic(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

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

func wsTopicHandle(w http.ResponseWriter, r *http.Request, read bool) error {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}

	l := rate.NewLimiter(rate.Every(wsRate), wsBurst)

	for {
		err = watchForTopics(r.Context(), c, l, read)
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			continue
		}

		if err != nil {
			return fmt.Errorf("failed to watch for topic with %v: %w", r.RemoteAddr, err)
		}
	}
}

func watchForTopics(ctx context.Context, c *websocket.Conn, l *rate.Limiter, read bool) error {
	ctx, cancel := context.WithTimeout(ctx, wsCtxTimeout)
	defer cancel()

	err := l.Wait(ctx)
	if err != nil {
		return err
	}

	if read {
		_, r, err := c.Reader(ctx)
		if err != nil {
			return err
		}

		b, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}

		topics <- b

		return nil
	}

	select {
	case b := <-topics:
		w, err := c.Writer(ctx, websocket.MessageText)
		if err != nil {
			return err
		}

		_, err = io.Copy(w, bytes.NewReader(b))
		if err != nil {
			return fmt.Errorf("failed to io.Copy: %w", err)
		}

		err = w.Close()

		return err
	case <-ctx.Done():
		return nil
	}
}

func main() {
	port := os.Getenv("WEBHOOK_PORT")
	if port == "" {
		panic("port to be passed as ENV variable")
	}

	router := mux.NewRouter().StrictSlash(true)

	if strings.EqualFold(os.Getenv("WEBHOOK_SCHEME"), "ws") {
		router.HandleFunc(checkTopicsPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := wsTopicHandle(w, r, false)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		router.HandleFunc(pushTopic, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := wsTopicHandle(w, r, true)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
	} else {
		router.HandleFunc(pushTopic, receiveTopic).Methods(http.MethodPost)
		router.HandleFunc(checkTopicsPath, checkTopics).Methods(http.MethodGet)
	}

	logger.Fatalf("webhook server start error %s", http.ListenAndServe(fmt.Sprintf(addressPattern, port), router))
}
