/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package apigw_ws

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/apigatewaymanagementapi"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
)

const webSocketScheme = "ws"

type OutboundClient struct {
	pool  *connPool
	prov  transport.Provider
	apiGw *apigatewaymanagementapi.ApiGatewayManagementApi
}

func NewOutbound() *OutboundClient {
	return &OutboundClient{}
}

func (cs *OutboundClient) Start(prov transport.Provider) error {
	cs.pool = getConnPool()
	cs.prov = prov

	stage := os.Getenv("STAGE")
	apiGwWebsocketDomain := os.Getenv("API_GATEWAY_WEBSOCKET_DOMAIN")
	serviceSlug := os.Getenv("SERVICE_SLUG")

	config := aws.Config{}

	if stage == "local" {
		endpoint := "http://host.docker.internal:3001"
		config = aws.Config{
			Endpoint:    &endpoint,
			Credentials: credentials.NewStaticCredentials("DEFAULT_ACCESS_KEY", "DEFAULT_SECRET", ""),
		}
		fmt.Printf(">>>>> WS Local Endpoint %s", endpoint)
	} else {
		endpoint := fmt.Sprintf("https://%s/%s", apiGwWebsocketDomain, serviceSlug)
		config = aws.Config{
			Endpoint: &endpoint,
		}
		fmt.Printf(">>>>> WS Remote Endpoint %s", endpoint)
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		Config:            config,
		SharedConfigState: session.SharedConfigEnable,
	}))

	cs.apiGw = apigatewaymanagementapi.New(sess, &config)

	fmt.Printf(">>>>>> WS Start\n")

	return nil
}

func (cs *OutboundClient) Send(data []byte, destination *service.Destination) (string, error) {
	// TODO use https://docs.aws.amazon.com/sdk-for-go/api/service/apigatewaymanagementapi/#ApiGatewayManagementApi.PostToConnection
	fmt.Printf(">>>>>> WS Send destination: %+v\n", destination)

	conn, channel, cleanup, err := cs.getConnection(destination)
	defer cleanup()

	if err != nil {
		return "", fmt.Errorf("get websocket connection : %w\n", err)
	}

	if channel != nil {
		//fmt.Printf(">>>>>>> Using Go channels\n")
		//*channel <- data
		//return "", err
	}

	_, err = cs.apiGw.PostToConnection(&apigatewaymanagementapi.PostToConnectionInput{
		ConnectionId: &conn,
		Data:         data,
	})

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	return "", err
}

func (cs *OutboundClient) Accept(url string) bool {
	fmt.Printf(">>>>>> WS Accept %v\n", url)
	return strings.HasPrefix(url, webSocketScheme)
}

func (cs *OutboundClient) AcceptRecipient(keys []string) bool {
	fmt.Printf(">>>>>> WS AcceptRecipient %v\n", keys)

	for _, v := range keys {
		// check if the connection exists for the key
		if c := cs.pool.fetch(v); c != "" {
			return true
		}
	}

	return false

}

func (cs *OutboundClient) getConnection(destination *service.Destination) (string, *chan []byte, func(), error) {
	var conn string
	var ch *chan []byte = nil

	// get the connection for the routing or recipient keys
	keys := destination.RecipientKeys
	if len(destination.RoutingKeys) != 0 {
		keys = destination.RoutingKeys
	}

	for _, v := range keys {
		wsChannel, ok := cs.pool.wsChannels[v]
		if ok {
			// channel is single-use only
			delete(cs.pool.wsChannels, v)
			ch = &wsChannel
		}

		if c := cs.pool.fetch(v); c != "" {
			conn = c

			break
		}
	}

	cleanup := func() {}

	if conn != "" {
		return conn, ch, cleanup, nil
	} else {
		return "", ch, cleanup, fmt.Errorf("Connection not found")
	}
}
