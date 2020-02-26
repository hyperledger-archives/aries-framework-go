/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webhook

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/internal/test/transportutil"
)

const topic = "basicmessages"
const topicWithLeadingSlash = "/" + topic
const localhost8080URL = "http://localhost:8080"

type clientData struct {
	clientHost                     string
	subscriberReceivedNotification chan struct{}
}

type msg struct {
	ConnectionID string `json:"connection_id"`
	MessageID    string `json:"message_id"`
	Content      string `json:"content"`
	State        string `json:"state"`
}

func TestNewWebNotifier(t *testing.T) {
	tests := []struct {
		testName  string
		urls      []string
		httpCount int
		wsCount   int
	}{{
		testName: "empty urls",
	}, {
		testName:  "http urls only",
		urls:      []string{"http://www.example.com", "https://www.example.com/abc"},
		httpCount: 2,
	},
		{
			testName: "websocket urls only",
			urls:     []string{"ws://www.example.com", "ws://www.example.com/abc", "wss://www.example.com/abc"},
			wsCount:  3,
		},
		{
			testName: "both http and websocket urls",
			urls: []string{"ws://www.example.com", "http://www.example.com/abc", "wss://www.example.com/abc",
				"https://www.example.com", "http://www.example.com/abc", "ws://www.example.com/abc"},
			httpCount: 3,
			wsCount:   3,
		},
	}

	for _, test := range tests {
		tc := test

		t.Run(tc.testName, func(t *testing.T) {
			w := NewWebNotifier(tc.urls)

			require.Len(t, w.httpURLs, tc.httpCount)
			require.Len(t, w.wsURLS, tc.wsCount)
		})
	}
}

func TestNotifyOneWebhook(t *testing.T) {
	testClientData := clientData{
		clientHost:                     randomURL(),
		subscriberReceivedNotification: make(chan struct{}),
	}

	go func(testClientData clientData) {
		err := runClient(testClientData)
		if err != nil {
			require.FailNow(t, err.Error())
		}
	}(testClientData)

	if err := transportutil.VerifyListener(testClientData.clientHost, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	testNotifier := NewWebNotifier([]string{fmt.Sprintf("http://%s", testClientData.clientHost)})

	err := testNotifier.Notify(topic, getTestBasicMessageJSON())

	require.NoError(t, err)

	select {
	case <-testClientData.subscriberReceivedNotification:
		// Pass
	case <-time.After(5 * time.Second):
		require.FailNow(t, "samplewebhookclient did not receive a notification")
	}
}

func TestNotifyMultipleWebhooks(t *testing.T) {
	clientData1 := clientData{
		clientHost:                     randomURL(),
		subscriberReceivedNotification: make(chan struct{}),
	}
	clientData2 := clientData{
		clientHost:                     randomURL(),
		subscriberReceivedNotification: make(chan struct{}),
	}

	allTestClientData := []clientData{clientData1, clientData2}

	for _, testClientData := range allTestClientData {
		go func(testClientData clientData) {
			err := runClient(testClientData)
			if err != nil {
				require.FailNow(t, err.Error())
			}
		}(testClientData)

		if err := transportutil.VerifyListener(testClientData.clientHost, 2*time.Second); err != nil {
			t.Fatal(err)
		}
	}

	testNotifier := NewWebNotifier([]string{fmt.Sprintf("http://%s", allTestClientData[0].clientHost),
		fmt.Sprintf("http://%s", allTestClientData[1].clientHost)})

	err := testNotifier.Notify(topic, getTestBasicMessageJSON())

	require.NoError(t, err)

	select {
	case <-allTestClientData[0].subscriberReceivedNotification:
		select {
		case <-allTestClientData[1].subscriberReceivedNotification:
			// Pass
		case <-time.After(5 * time.Second):
			require.FailNow(t, "samplewebhookclient2 did not receive a notification")
		}
	case <-time.After(5 * time.Second):
		require.FailNow(t, "samplewebhookclient1 did not receive a notification")
	}
}

func TestNotifyUnsupportedProtocol(t *testing.T) {
	testNotifier := NewWebNotifier([]string{"badURL"})

	err := testNotifier.Notify(topic, getTestBasicMessageJSON())

	require.Contains(t, err.Error(), "unsupported protocol")
}

func TestNotifyCorrectJSON(t *testing.T) {
	clientHost := randomURL()

	go func() {
		err := listenAndStopAfterReceivingNotification(clientHost)
		if err != nil {
			require.FailNow(t, err.Error())
		}
	}()

	if err := transportutil.VerifyListener(clientHost, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	err := notifyHTTP(fmt.Sprintf("http://%s%s", clientHost, topicWithLeadingSlash), getTestBasicMessageJSON())
	require.NoError(t, err)
}

func TestNotifyMalformedJSON(t *testing.T) {
	clientHost := randomURL()

	go func() {
		err := listenAndStopAfterReceivingNotification(clientHost)
		if err != nil {
			require.FailNow(t, err.Error())
		}
	}()

	if err := transportutil.VerifyListener(clientHost, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	malformedBasicMessage := []byte(`
   {
       "thisIsWrong",
		"state": "SomeState"
   }
		`)
	err := notifyHTTP(fmt.Sprintf("http://%s%s", clientHost, topicWithLeadingSlash), malformedBasicMessage)
	require.Contains(t, err.Error(), "400 Bad Request")
}

func TestWebhookNotificationMalformedURL(t *testing.T) {
	err := notifyHTTP("%", nil)
	require.Contains(t, err.Error(), `invalid URL escape "%"`)
}

func TestWebhookNotificationNoResponse(t *testing.T) {
	err := notifyHTTP(localhost8080URL, nil)
	require.Contains(t, err.Error(), "connection refused")
}

func TestNotifyEmptyTopic(t *testing.T) {
	testNotifier := NewWebNotifier([]string{localhost8080URL})

	err := testNotifier.Notify("", getTestBasicMessageJSON())

	require.Equal(t, emptyTopicErrMsg, err.Error())
}

func TestNotifyEmptyMessage(t *testing.T) {
	testNotifier := NewWebNotifier([]string{localhost8080URL})

	err := testNotifier.Notify("someTopic", nil)

	require.Equal(t, emptyMessageErrMsg, err.Error())
}

func TestNotifyMultipleErrors(t *testing.T) {
	testNotifier := NewWebNotifier([]string{"badURL1", "badURL2"})

	err := testNotifier.Notify("someTopic", []byte(`someMessage`))

	require.Contains(t, err.Error(), `failed to post notification to badURL1/someTopic: `+
		`Post badURL1/someTopic: unsupported protocol scheme ""`)
	require.Contains(t, err.Error(), `failed to post notification to badURL2/someTopic: `+
		`Post badURL2/someTopic: unsupported protocol scheme ""`)
}

func TestWebhookNotificationClient500Response(t *testing.T) {
	clientHost := randomURL()
	clientHandlerPattern := "/webhookListen6"
	srv := &http.Server{Addr: clientHost, Handler: http.DefaultServeMux}

	http.HandleFunc(clientHandlerPattern, func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusInternalServerError)
	})

	go func() {
		err := srv.ListenAndServe()
		require.NoError(t, err)
	}()

	if err := transportutil.VerifyListener(clientHost, 2*time.Second); err != nil {
		t.Fatal(err)
	}

	err := notifyHTTP(fmt.Sprintf("http://%s%s", clientHost, clientHandlerPattern), nil)
	require.Contains(t, err.Error(), "500 Internal Server Error", err.Error())
}

func TestWebsocketNotifier(t *testing.T) {
	topics := make(chan []byte, 1)

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	defer func() {
		e := l.Close()
		if e != nil {
			t.Log("failed to close listener", e)
		}
	}()

	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e := topicHandle(w, r, topics)
			if err != nil {
				t.Fatal(e)
			}
		}),
	}

	defer func() {
		e := s.Close()
		if e != nil {
			t.Log("failed to close server", e)
		}
	}()

	go func() {
		e := s.Serve(l)
		if e != http.ErrServerClosed {
			t.Log(err)
		}
	}()

	w := NewWebNotifier([]string{"ws://" + l.Addr().String()})

	msg := struct {
		ID      string
		Message string
	}{
		ID:      uuid.New().String(),
		Message: "Hello",
	}

	msgBytes, err := json.Marshal(&msg)
	require.NotEmpty(t, msgBytes)
	require.NoError(t, err)

	err = w.Notify("test-topic", msgBytes)
	require.NoError(t, err)

	select {
	case m := <-topics:
		rm := struct {
			ID      string
			Message string
		}{}
		err = json.Unmarshal(m, &rm)
		require.NoError(t, err)
		require.Equal(t, rm, msg)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for topic")
	}
}

func getTestBasicMessageJSON() []byte {
	return []byte(`
   {
       "connection_id": "SomeConnectionID",
       "message_id": "SomeMessageId",
		"content": "SomeContent",
		"state": "SomeState"
   }
		`)
}

func runClient(testClientData clientData) error {
	err := listenAndStopAfterReceivingNotification(testClientData.clientHost)
	if err != nil {
		return err
	}

	close(testClientData.subscriberReceivedNotification)

	return nil
}

func listenAndStopAfterReceivingNotification(addr string) error {
	m := http.NewServeMux()
	srv := &http.Server{Addr: addr, Handler: m}
	ctx, cancel := context.WithCancel(context.Background())

	m.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
		response, err := ioutil.ReadAll(req.Body)
		if err == nil {
			var receivedMessage msg
			err = json.Unmarshal(response, &receivedMessage)
			if err != nil {
				resp.WriteHeader(http.StatusBadRequest)
			}
			expectedTestBasicMessage := msg{
				ConnectionID: "SomeConnectionID",
				MessageID:    "SomeMessageId",
				Content:      "SomeContent",
				State:        "SomeState",
			}
			if receivedMessage != expectedTestBasicMessage {
				resp.WriteHeader(http.StatusBadRequest)
			}
		} else {
			resp.WriteHeader(http.StatusBadRequest)
		}
		cancel()
	})

	errorChannel := make(chan error)

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			errorChannel <- err

			cancel()
		}
	}()

	select {
	case <-ctx.Done():
		if err := srv.Shutdown(ctx); err != nil && err != context.Canceled {
			return fmt.Errorf("failed to shutdown sample webhook client server: %s", err)
		}

		return nil
	case err := <-errorChannel:
		return fmt.Errorf("webhook sample client failed: %s", err)
	}
}

func randomURL() string {
	return fmt.Sprintf("localhost:%d", transportutil.GetRandomPort(3))
}

func topicHandle(w http.ResponseWriter, r *http.Request, topics chan []byte) error {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}

	l := rate.NewLimiter(rate.Every(time.Millisecond*100), 10)

	for {
		err := watchForTopics(r.Context(), c, l, topics)

		if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
			continue
		}

		if err != nil {
			return fmt.Errorf("failed to test with %v: %w", r.RemoteAddr, err)
		}
	}
}

func watchForTopics(ctx context.Context, c *websocket.Conn, l *rate.Limiter, topics chan []byte) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	err := l.Wait(ctx)
	if err != nil {
		return err
	}

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
