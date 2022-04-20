/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gorilla/mux"
)

func CreateRouter() (*mux.Router, error) {
	router, err := RegisterRoutes(BaseRouter())
	if err != nil {
		return nil, err
	}

	return router, nil
}

func Handler(ctx context.Context, event map[string]interface{}) (APIGatewayProxyResponse, error) {
	log.Printf("Creating Router")
	router, err := CreateRouter()
	if err != nil {
		fmt.Printf("Creating Router error: %s\n", err)
		return APIGatewayProxyResponse{StatusCode: 500}, err
	}
	log.Printf("Creating Adapter")
	adapter := New(router)

	log.Printf("Proxying Request...")
	log.Printf("!!! Received event: %+v", event)
	response, err := adapter.ProxyInterfaceWithContext(ctx, event)
	if err != nil {
		fmt.Printf("Creating Router error: %s\n", err)
		return APIGatewayProxyResponse{StatusCode: 500}, err
	}

	log.Printf("Success! Response: %+v\n", response)

	return response, nil
}

func main() {
	log.Printf("Starting Lambda function")
	lambda.Start(Handler)
}
