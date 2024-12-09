/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package apigw_ws

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

const (
	// TODO configure ping request frequency.
	pingFrequency = 30 * time.Second

	// legacyKeyLen key length.
	legacyKeyLen = 32
)

type connPool struct {
	client     *dynamodb.DynamoDB
	tableName  string
	packager   transport.Packager
	msgHandler transport.InboundMessageHandler
	wsChannels map[string]chan []byte
}

var (
	singletonConnPool *connPool
)

func getConnPool() *connPool {
	if singletonConnPool == nil {
		stage := os.Getenv("STAGE")
		config := aws.Config{}

		if stage == "local" {
			endpoint := "http://host.docker.internal:8100"
			config = aws.Config{
				Endpoint:    &endpoint,
				Credentials: credentials.NewStaticCredentials("DEFAULT_ACCESS_KEY", "DEFAULT_SECRET", ""),
			}
		}

		sess := session.Must(session.NewSessionWithOptions(session.Options{
			Config:            config,
			SharedConfigState: session.SharedConfigEnable,
		}))

		singletonConnPool = &connPool{
			client: dynamodb.New(sess),
			tableName: tableName("wsconnections"),
			wsChannels: make(map[string]chan []byte),
		}
	}

	return singletonConnPool
}

type dbEntry struct {
	Key          string
	ConnectionID string
}

func tableName(name string) string {
	stage := os.Getenv("STAGE")
	serviceName := os.Getenv("SERVICE_NAME")

	return fmt.Sprintf("%s-%s-%s", stage, serviceName, strings.ToLower(name))
}

func (d *connPool) add(verKey string, connId string, respChannel chan []byte) {
	avItem, err := dynamodbattribute.MarshalMap(dbEntry{
		Key:   verKey,
		ConnectionID: connId,
	})
	if err != nil {
		fmt.Printf("Put error: %s\n", err)
	}

	_, err = d.client.PutItem(&dynamodb.PutItemInput{
		TableName: &d.tableName,
		Item:      avItem,
	})

	if err != nil {
		fmt.Printf("Put error: %s\n", err)
	}

	d.wsChannels[verKey] = respChannel
}

func (d *connPool) fetch(verKey string) string {
	fmt.Printf("Fetching key %s\n", verKey)

	result, err := d.client.GetItem(&dynamodb.GetItemInput{
		TableName: &d.tableName,
		Key: map[string]*dynamodb.AttributeValue{
			"Key": {
				S: &verKey,
			},
		},
	})

	if err != nil {
		fmt.Printf("Get error: %s\n", err)
		return ""
	}

	if result.Item == nil {
		return ""
	}

	var item dbEntry
	if err := dynamodbattribute.UnmarshalMap(result.Item, &item); err != nil {
		fmt.Printf("Get error: %s\n", err)
		return ""
	}

	return item.ConnectionID
}

func (d *connPool) remove(verKey string) {
	if verKey == "" {
		return
	}

	fmt.Printf("Delete verKey %s\n", verKey)
	delete(d.wsChannels, verKey)

	_, err := d.client.DeleteItem(&dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Key": {
				S: &verKey,
			},
		},
		TableName: &d.tableName,
	})

	if err != nil {
		fmt.Printf("Delete error: %s\n", err)
	}
}

func (d *connPool) addKey(unpackMsg *transport.Envelope, trans *decorator.Transport, connId string, respChannel chan []byte) {
	var fromKey string

	if len(unpackMsg.FromKey) == legacyKeyLen {
		fromKey, _ = fingerprint.CreateDIDKey(unpackMsg.FromKey)
	} else {
		fromPubKey := &cryptoapi.PublicKey{}

		err := json.Unmarshal(unpackMsg.FromKey, fromPubKey)
		if err != nil {
			log.Printf("addKey: unpackMsg.FromKey is not a public key [err: %s]. "+
				"It will not be added to the ws connection.", err)
		} else {
			fromKey = fromPubKey.KID
		}
	}

	if trans.ReturnRoute != nil && trans.ReturnRoute.Value == decorator.TransportReturnRouteAll {
		if fromKey != "" {
			d.add(fromKey, connId, respChannel)
		}

		keyAgreementIDs := d.checkKeyAgreementIDs(unpackMsg.Message)

		for _, kaID := range keyAgreementIDs {
			d.add(kaID, connId, respChannel)
		}

		if fromKey == "" && len(keyAgreementIDs) == 0 {
			log.Printf("addKey: no key is linked to ws connection.")
		}
	}
}

func (d *connPool) checkKeyAgreementIDs(message []byte) []string {
	req := &didexchange.Request{}

	err := json.Unmarshal(message, req)
	if err != nil {
		log.Printf("unmarshal request message failed, ignoring keyAgreementID, err: %v", err)

		return nil
	}

	if req.DocAttach == nil {
		log.Printf("fetch message attachment/attachmentData is empty. Skipping adding KeyAgreementID to the pool.")

		return nil
	}

	data, err := req.DocAttach.Data.Fetch()
	if err != nil {
		log.Printf("fetch message attachment data failed, ignoring keyAgreementID, err: %v", err)

		return nil
	}

	doc := &did.Doc{}

	err = json.Unmarshal(data, doc)
	if err != nil {
		log.Printf("unmarshal DID doc from attachment data failed, ignoring keyAgreementID, err: %v", err)

		return nil
	}

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
