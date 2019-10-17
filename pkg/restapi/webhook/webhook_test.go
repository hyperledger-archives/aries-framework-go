/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type clientData struct {
	clientHost                     string
	clientHandlerPattern           string
	subscriberReceivedNotification chan struct{}
}

func TestWebhookDispatcherOneWebhook(t *testing.T) {
	testClientData := clientData{
		clientHost:                     randomURL(),
		clientHandlerPattern:           "/webhookListen1",
		subscriberReceivedNotification: make(chan struct{}),
	}

	go func() {
		err := listenAndStopAfterReceivingNotification(testClientData.clientHost, testClientData.clientHandlerPattern)
		if err != nil {
			require.FailNow(t, err.Error())
		} else {
			close(testClientData.subscriberReceivedNotification)
		}
	}()

	if err := listenFor(testClientData.clientHost); err != nil {
		t.Fatal(err)
	}

	StartWebhookDispatcher([]string{fmt.Sprintf("http://%s%s", testClientData.clientHost,
		testClientData.clientHandlerPattern)})

	select {
	case <-testClientData.subscriberReceivedNotification:
		// Pass
	case <-time.After(5 * time.Second):
		require.FailNow(t, "samplewebhookclient did not receive a notification")
	}
}

func TestWebhookDispatcherMultipleWebhooks(t *testing.T) {
	clientData1 := clientData{
		clientHost:                     randomURL(),
		clientHandlerPattern:           "/webhookListen2",
		subscriberReceivedNotification: make(chan struct{}),
	}
	clientData2 := clientData{
		clientHost:                     randomURL(),
		clientHandlerPattern:           "/webhookListen3",
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

		if err := listenFor(testClientData.clientHost); err != nil {
			t.Fatal(err)
		}
	}

	StartWebhookDispatcher([]string{fmt.Sprintf("http://%s%s", allTestClientData[0].clientHost,
		allTestClientData[0].clientHandlerPattern),
		fmt.Sprintf("http://%s%s", allTestClientData[1].clientHost, allTestClientData[1].clientHandlerPattern)})

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

func runClient(testClientData clientData) error {
	err := listenAndStopAfterReceivingNotification(testClientData.clientHost, testClientData.clientHandlerPattern)
	if err != nil {
		return err
	}
	close(testClientData.subscriberReceivedNotification)
	return nil
}

func TestWebhookSendNotification(t *testing.T) {
	clientHost := randomURL()
	clientHandlerPattern := "/webhookListen4"

	go func() {
		err := listenAndStopAfterReceivingNotification(clientHost, clientHandlerPattern)
		if err != nil {
			require.FailNow(t, err.Error())
		}
	}()

	if err := listenFor(clientHost); err != nil {
		t.Fatal(err)
	}

	err := sendNotification(fmt.Sprintf("http://%s%s", clientHost, clientHandlerPattern))
	require.NoError(t, err)
}

func TestWebhookNotificationMalformedURL(t *testing.T) {
	err := sendNotification("%")
	require.Contains(t, err.Error(), `invalid URL escape "%"`)
}

func TestWebhookNotificationClientURLNoResponse(t *testing.T) {
	err := sendNotification("http://localhost:8080")
	require.Contains(t, err.Error(), "connection refused")
}

func TestWebhookNotificationClient500Response(t *testing.T) {
	clientHost := randomURL()
	clientHandlerPattern := "/webhookListen5"
	srv := &http.Server{Addr: clientHost, Handler: http.DefaultServeMux}

	http.HandleFunc(clientHandlerPattern, func(resp http.ResponseWriter, req *http.Request) {
		resp.WriteHeader(http.StatusInternalServerError)
	})

	go func() {
		err := srv.ListenAndServe()
		require.NoError(t, err)
	}()

	if err := listenFor(clientHost); err != nil {
		t.Fatal(err)
	}

	err := sendNotification(fmt.Sprintf("http://%s%s", clientHost, clientHandlerPattern))
	require.Contains(t, err.Error(), "500 Internal Server Error", err.Error())
}

func randomURL() string {
	return fmt.Sprintf("localhost:%d", mustGetRandomPort(3))
}

func mustGetRandomPort(n int) int {
	for ; n > 0; n-- {
		port, err := getRandomPort()
		if err != nil {
			continue
		}
		return port
	}
	panic("cannot acquire the random port")
}

func getRandomPort() (int, error) {
	const network = "tcp"
	addr, err := net.ResolveTCPAddr(network, "localhost:0")
	if err != nil {
		return 0, err
	}
	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, err
	}
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func listenFor(host string) error {
	timeout := time.After(2 * time.Second)
	for {
		select {
		case <-timeout:
			return errors.New("timeout: server is not available")
		default:
			conn, err := net.Dial("tcp", host)
			if err != nil {
				continue
			}
			if err := conn.Close(); err != nil {
				return err
			}
			return nil
		}
	}
}

func listenAndStopAfterReceivingNotification(addr, handlerPattern string) error {
	srv := &http.Server{Addr: addr, Handler: http.DefaultServeMux}

	ctx, cancel := context.WithCancel(context.Background())
	http.HandleFunc(handlerPattern, func(resp http.ResponseWriter, req *http.Request) {
		logger.Infof("Sample webhook client just received webhook notification")
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
