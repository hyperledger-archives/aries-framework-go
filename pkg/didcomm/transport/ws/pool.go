/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport/internal"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/peer"
)

const (
	// TODO configure ping request frequency.
	pingFrequency = 30 * time.Second

	// legacyKeyLen key length.
	legacyKeyLen = 32
)

type connPool struct {
	connMap map[string]*websocket.Conn
	sync.RWMutex
	packager   transport.Packager
	msgHandler transport.InboundMessageHandler
}

// nolint: gochecknoglobals
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

func (d *connPool) remove(verKey string) {
	d.Lock()
	defer d.Unlock()

	delete(d.connMap, verKey)
}

func (d *connPool) listener(conn *websocket.Conn, outbound bool) {
	verKeys := []string{}

	defer d.close(conn, verKeys)

	go keepConnAlive(conn, outbound, pingFrequency)

	for {
		_, message, err := conn.Read(context.Background())
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				logger.Errorf("Error reading request message: %v", err)
			}

			break
		}

		unpackMsg, err := internal.UnpackMessage(message, d.packager, "ws")
		if err != nil {
			logger.Errorf("%w", err)

			continue
		}

		trans := &decorator.Transport{}

		err = json.Unmarshal(unpackMsg.Message, trans)
		if err != nil {
			logger.Errorf("unmarshal transport decorator : %v", err)
		}

		d.addKey(unpackMsg, trans, conn)

		messageHandler := d.msgHandler

		err = messageHandler(unpackMsg)
		if err != nil {
			logger.Errorf("incoming msg processing failed: %v", err)
		}
	}
}

func (d *connPool) addKey(unpackMsg *transport.Envelope, trans *decorator.Transport, conn *websocket.Conn) {
	var fromKey string

	if len(unpackMsg.FromKey) == legacyKeyLen {
		fromKey, _ = fingerprint.CreateDIDKey(unpackMsg.FromKey)
	} else {
		fromPubKey := &cryptoapi.PublicKey{}

		err := json.Unmarshal(unpackMsg.FromKey, fromPubKey)
		if err != nil {
			logger.Debugf("addKey: unpackMsg.FromKey is not a public key [err: %s]. "+
				"It will not be added to the ws connection.", err)
		} else {
			fromKey = fromPubKey.KID
		}
	}

	if trans.ReturnRoute != nil && trans.ReturnRoute.Value == decorator.TransportReturnRouteAll {
		if fromKey != "" {
			d.add(fromKey, conn)
		}

		keyAgreementIDs := checkKeyAgreementIDs(unpackMsg.Message)

		for _, kaID := range keyAgreementIDs {
			d.add(kaID, conn)
		}

		if fromKey == "" && len(keyAgreementIDs) == 0 {
			logger.Warnf("addKey: no key is linked to ws connection.")
		}
	}
}

func (d *connPool) close(conn *websocket.Conn, verKeys []string) {
	if err := conn.Close(websocket.StatusNormalClosure,
		"closing the connection"); websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		logger.Errorf("connection close error")
	}

	for _, v := range verKeys {
		d.remove(v)
	}
}

func checkKeyAgreementIDs(message []byte) []string {
	var err1, err2 error

	var doc *did.Doc

	doc, err1 = didCommV1PeerDoc(message)

	if err1 != nil {
		doc, err2 = didCommV2PeerDoc(message)
	}

	if err1 != nil && err2 != nil {
		logger.Debugf("failed to find a DIDComm DID doc in websocket message, will not add any keyAgreementIDs."+
			" DIDComm V1 parse result=[%s], DIDComm V2 parse result=[%s]", err1.Error(), err2.Error())

		return nil
	}

	return docKeyAgreementIDs(doc)
}

func didCommV1PeerDoc(message []byte) (*did.Doc, error) {
	req := &didexchange.Request{}

	err := json.Unmarshal(message, req)
	if err != nil {
		return nil, fmt.Errorf("unmarshal request message failed: %w", err)
	}

	if req.DocAttach == nil {
		return nil, fmt.Errorf("fetch message attachment/attachmentData is empty")
	}

	data, err := req.DocAttach.Data.Fetch()
	if err != nil {
		return nil, fmt.Errorf("fetch message attachment data failed: %w", err)
	}

	doc := &did.Doc{}

	err = json.Unmarshal(data, doc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal DID doc from attachment data failed: %w", err)
	}

	return doc, nil
}

type msgFromField struct {
	From string `json:"from"`
}

func didCommV2PeerDoc(message []byte) (*did.Doc, error) {
	msg := &msgFromField{}

	err := json.Unmarshal(message, msg)
	if err != nil {
		return nil, fmt.Errorf("unmarshal message as didcomm/v2 failed: %w", err)
	}

	if msg.From == "" {
		return nil, fmt.Errorf("message has no didcomm/v2 'from' field")
	}

	didURL, err := did.ParseDIDURL(msg.From)
	if err != nil {
		return nil, fmt.Errorf("'from' field not did url: %w", err)
	}

	if didURL.Method != "peer" {
		return nil, fmt.Errorf("'from' DID not peer DID")
	}

	stateQueries := didURL.Queries["initialState"]
	if len(stateQueries) == 0 {
		return nil, fmt.Errorf("peer DID URL has no initialState parameter")
	}

	doc, err := peer.DocFromGenesisDelta(stateQueries[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse initialState into DID doc: %w", err)
	}

	return doc, nil
}

func docKeyAgreementIDs(doc *did.Doc) []string {
	var keyAgreementIDs []string

	for _, ka := range doc.KeyAgreement {
		kaID := ka.VerificationMethod.ID
		if strings.HasPrefix(kaID, "#") {
			kaID = doc.ID + kaID
		}

		keyAgreementIDs = append(keyAgreementIDs, kaID)
	}

	return keyAgreementIDs
}
