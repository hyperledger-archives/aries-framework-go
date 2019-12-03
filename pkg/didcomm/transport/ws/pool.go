/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"encoding/json"
	"sync"

	"nhooyr.io/websocket"

	commtransport "github.com/hyperledger/aries-framework-go/pkg/didcomm/common/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

type connPool struct {
	connMap map[string]*websocket.Conn
	sync.RWMutex
	packager   commtransport.Packager
	msgHandler transport.InboundMessageHandler
}

// nolint gochecknoglobals
var pool = make(map[string]*connPool)

func getConnPool(prov transport.Provider) *connPool {
	id := prov.AriesFrameworkID()

	if _, ok := pool[id]; !ok {
		pool[id] = &connPool{
			connMap:    make(map[string]*websocket.Conn),
			packager:   prov.Packager(),
			msgHandler: prov.InboundMessageHandler(),
		}
	}

	return pool[id]
}

func (d *connPool) add(verKey string, wsConn *websocket.Conn) {
	d.Lock()
	defer d.Unlock()

	d.connMap[verKey] = wsConn
}

func (d *connPool) fetch(verKey string) *websocket.Conn {
	d.RLock()
	defer d.RUnlock()

	return d.connMap[verKey]
}

func (d *connPool) listener(conn *websocket.Conn) {
	defer close(conn)

	for {
		_, message, err := conn.Read(context.Background())
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				logger.Errorf("Error reading request message: %v", err)
			}

			break
		}

		unpackMsg, err := d.packager.UnpackMessage(message)

		if err != nil {
			logger.Errorf("failed to unpack msg: %v", err)

			continue
		}

		trans := &decorator.Transport{}

		err = json.Unmarshal(unpackMsg.Message, trans)
		if err != nil {
			logger.Errorf("unmarshal transport decorator : %v", err)
		}

		if trans != nil && trans.ReturnRoute != nil && trans.ReturnRoute.Value == "all" {
			d.add(unpackMsg.FromVerKey, conn)
		}

		messageHandler := d.msgHandler

		err = messageHandler(unpackMsg.Message)
		if err != nil {
			logger.Errorf("incoming msg processing failed: %v", err)
		}
	}
}

func close(conn *websocket.Conn) {
	if err := conn.Close(websocket.StatusNormalClosure,
		"closing the connection"); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		logger.Errorf("connection close error")
	}
}
