/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Boran Car <boran.car@gmail.com>. All Rights Reserved.
Copyright Christian Nuss <christian@scaffold.ly>, Founder, Scaffoldly LLC. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"log"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/awslabs/aws-lambda-go-api-proxy/core"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
)

type APIGatewayProxyResponse struct {
	StatusCode        int                 `json:"statusCode"`
	Headers           map[string]string   `json:"headers"`
	MultiValueHeaders map[string][]string `json:"multiValueHeaders"`
	Body              string              `json:"body,omitempty"`
	IsBase64Encoded   bool                `json:"isBase64Encoded,omitempty"`
}

type GorillaMuxAdapter struct {
	core.RequestAccessor
	router *mux.Router
}

func BaseRouter() *mux.Router {
	log.Printf("Creating base router")
	router := mux.NewRouter()
	return router
}

func New(router *mux.Router) *GorillaMuxAdapter {
	return &GorillaMuxAdapter{
		router: router,
	}
}

// func (h *GorillaMuxAdapter) Proxy(event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
// 	req, err := h.ProxyEventToHTTPRequest(event)
// 	return h.proxyInternal(req, err)
// }

// func (h *GorillaMuxAdapter) ProxyWithContext(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
// 	req, err := h.EventToRequestWithContext(ctx, event)
// 	return h.proxyInternal(req, err)
// }

func (h *GorillaMuxAdapter) ProxyInterfaceWithContext(ctx context.Context, event map[string]interface{}) (APIGatewayProxyResponse, error) {
	evt := events.APIGatewayProxyRequest{}

	err := mapstructure.Decode(event, &evt)
	if err != nil {
		return APIGatewayProxyResponse(core.GatewayTimeout()), core.NewLoggedError("Could not convert event: %v", err)
	}
	websocket := false
	if _, ok := evt.Headers["Sec-WebSocket-Version"]; ok {
		websocket = true
	}

	if _, ok := event["requestContext"].(map[string]interface{})["connectionId"]; ok {
		websocket = true
	}

	if websocket {
		log.Printf("Extracting websocket data from event")
		// Convert the V2 Websocket Event into a V1 HTTP Event
		//   + the Path to /ws
		//   + the Connection ID to the headers as X-Connection-Id
		//   ~ connect$ ==> PUT
		//   ~ disconnect$ ==> DELETE
		//   ~ all other routes ==> POST

		websocketEvt := events.APIGatewayWebsocketProxyRequest{}
		err = mapstructure.Decode(event, &websocketEvt)
		if err != nil {
			return APIGatewayProxyResponse(core.GatewayTimeout()), core.NewLoggedError("Could not convert websocket event: %v", err)
		}

		evt.Path = "/ws"
		if evt.Headers == nil {
			evt.Headers = map[string]string{}
			evt.MultiValueHeaders = map[string][]string{}
		}
		evt.Headers["X-ConnectionId"] = websocketEvt.RequestContext.ConnectionID
		evt.MultiValueHeaders["X-ConnectionId"] = []string{websocketEvt.RequestContext.ConnectionID}

		if websocketEvt.RequestContext.RouteKey == "$connect" {
			evt.HTTPMethod = http.MethodPut
		} else if websocketEvt.RequestContext.RouteKey == "$disconnect" {
			evt.HTTPMethod = http.MethodDelete
		} else {
			evt.HTTPMethod = http.MethodPost
		}
	}

	log.Printf("Event: %+v", evt)

	req, err := h.EventToRequestWithContext(ctx, evt)
	if err != nil {
		return APIGatewayProxyResponse(core.GatewayTimeout()), core.NewLoggedError("Error converting event to request: %v", err)
	}
	log.Printf("Request: %+v", req)
	return h.proxyInternal(req, err)
}

func (h *GorillaMuxAdapter) proxyInternal(req *http.Request, err error) (APIGatewayProxyResponse, error) {
	if err != nil {
		return APIGatewayProxyResponse(core.GatewayTimeout()), core.NewLoggedError("Could not convert proxy event to request: %v", err)
	}

	w := core.NewProxyResponseWriter()
	h.router.ServeHTTP(http.ResponseWriter(w), req)

	resp, err := w.GetProxyResponse()
	if err != nil {
		return APIGatewayProxyResponse(core.GatewayTimeout()), core.NewLoggedError("Error while generating proxy response: %v", err)
	}

	return APIGatewayProxyResponse(resp), nil
}
