/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webnotifier

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"nhooyr.io/websocket"

	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
)

// WSNotifier is a dispatcher capable of notifying multiple subscribers via WebSocket.
type WSNotifier struct {
	conns     []*websocket.Conn
	connsLock sync.RWMutex
	handlers  []rest.Handler
}

// NewWSNotifier returns a new instance of an WSNotifier.
func NewWSNotifier(path string) *WSNotifier {
	n := WSNotifier{
		conns: []*websocket.Conn{},
	}

	n.registerHandler(path)

	return &n
}

// Notify sends the given message to all of the WS clients.
// If multiple errors are encountered, then the first one is returned.
func (n *WSNotifier) Notify(topic string, message []byte) error {
	if topic == "" {
		return fmt.Errorf(emptyTopicErrMsg)
	}

	if len(message) == 0 {
		return fmt.Errorf(emptyMessageErrMsg)
	}

	n.connsLock.RLock()
	conns := make([]*websocket.Conn, len(n.conns))
	copy(conns, n.conns)
	n.connsLock.RUnlock()

	topicMsg, err := PrepareTopicMessage(topic, message)
	if err != nil {
		return fmt.Errorf(failedToCreateErrMsg, err)
	}

	var allErrs error

	for _, conn := range conns {
		// TODO parent ctx should be an argument to Notify https://github.com/hyperledger/aries-framework-go/issues/1355
		err := notifyWS(context.Background(), conn, topicMsg)
		allErrs = appendError(allErrs, err)
	}

	return nil
}

func notifyWS(parent context.Context, conn *websocket.Conn, message []byte) error {
	ctx, cancel := context.WithTimeout(parent, notificationSendTimeout)
	defer cancel()

	return conn.Write(ctx, websocket.MessageText, message)
}

func (n *WSNotifier) handleWS(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("websocket notification client connected")

	// TODO Allow user to enable InsecureSkipVerify https://github.com/hyperledger/aries-framework-go/issues/928
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		logger.Infof("failed to upgrade the websocket notification connection : %v", err)
	}

	n.connsLock.Lock()
	n.conns = append(n.conns, conn)
	n.connsLock.Unlock()

	n.monitorWSConn(context.Background(), conn)
}

func (n *WSNotifier) monitorWSConn(ctx context.Context, conn *websocket.Conn) {
	logger.Debugf("websocket notification client established")

	_, _, err := conn.Reader(ctx)
	if err != nil {
		if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
			logger.Infof("reading from websocket notification client failed: %v", err)
		}
	}

	err = conn.Close(websocket.StatusPolicyViolation, "unexpected message")
	if err != nil {
		logger.Infof("closing websocket notification client failed: %v", err)
	}

	n.removeConn(conn)
}

func (n *WSNotifier) removeConn(conn *websocket.Conn) {
	logger.Debugf("websocket notification client dropped")

	n.connsLock.Lock()
	defer n.connsLock.Unlock()

	var conns []*websocket.Conn
	for _, c := range n.conns {
		if c != conn {
			conns = append(conns, c)
		}
	}

	n.conns = conns
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (n *WSNotifier) registerHandler(path string) {
	n.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(path, http.MethodGet, n.handleWS),
	}
}

// GetRESTHandlers returns all REST handlers provided by notifier.
func (n *WSNotifier) GetRESTHandlers() []rest.Handler {
	return n.handlers
}
