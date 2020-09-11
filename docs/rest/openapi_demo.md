# Run OpenAPI demo

## Setup
Please go through the [prerequisites](../test/build.md#Prerequisites-(for-running-tests-and-demos)) and launch the demo by running the following make target from project root directory.

`make run-openapi-demo`

Once both agents are up, click on the agent specific urls to launch the OpenAPI interface.

[Alice OpenAPI Interface](http://localhost:8089/openapi/)

[Bob OpenAPI Interface](http://localhost:9089/openapi/)

## Steps for DIDExchange 
1. On Alice agent, generate an invitation with `HTTP POST /connections/create-invitation` and copy the invitation from the response. Refer [here](#Invitation) for sample invitation json. 
2. On Bob agent, save the invitation received from Alice with `HTTP POST /connections/receive-invitation` API. Note down the connection ID generated in the response.
3. `HTTP GET /connections/{id}` with the connection ID from the previous step fetches the new connection record. The state of this record should be `invited`. Refer [here](#Connection-by-ID-API-Response) for sample response. 
4. Also, `HTTP GET /connections` fetches all connection records. There should be one connection with state "invited". Refer [here](#Connections-API-Response) for sample response.
5. On Bob agent, accept the Invitation from Alice by sending connection ID with `HTTP POST /connections/{id}/accept-invitation`. After this, the state of the connection should be updated to `requested`.
6. On Alice agent, fetch all connections with `HTTP GET /connections`. There will be one record with status `requested` (request from Bob). Get the connection ID of this record.
7. On Alice agent, accept the Bob's request with `HTTP POST /connections/{id}/accept-request` API. 
8. Calling `HTTP GET /connections/{id}` on both agents should show the connections with state `completed`. Alice and Bob are now connected.

## Steps for DIDExchange through DIDComm Routers 
[Carl OpenAPI Interface](http://localhost:10089/openapi/)

[Carl's Router OpenAPI Interface](http://localhost:10099/openapi/)

[Dave OpenAPI Interface](http://localhost:10069/openapi/)

[Dave's Router OpenAPI Interface](http://localhost:10079/openapi/)

1. Create connection between Carl and his router through [DIDExchange](#Steps-for-DIDExchange) (substitute Carl with Bob and Carl's router with Alice while going through the steps). 
2. Create connection between Dave and his router through [DIDExchange](#Steps-for-DIDExchange) (substitute Dave with Bob and Dave's router with Alice while going through the steps). 
3. On Carl's agent, register the router with `HTTP POST /route/register` API by passing his router's connection ID.
4. On Carl's agent, using `HTTP GET /route/connection` verify that the connectionID matches with previously set connection ID. 
5. On Carl's agent, generate an invitation using `HTTP POST /connections/create-invitation` API. Observe that the service endpoint in the invitation is `http://carl.router.aries.example.com:10091`, which is the endpoint of Carl's router.
6. On Dave's agent, register the router with `HTTP POST /route/register` API by passing his router's connection ID.
7. On Dave's agent, using `HTTP GET /route/connection` verify that the connectionID matches with previously set connection ID. 
8. On Dave's agent, generate an invitation using `HTTP POST /connections/create-invitation` API. Observe that the service endpoint in the invitation is `http://dave.router.aries.example.com:10091`, which is the endpoint of Dave's router.
9. Create connection between Carl and Dave through [DIDExchange](#Steps-for-DIDExchange) (substitute Carl with Bob and Dave with Alice while going through the steps).
  
Notes:
1. The invitation needs to be created by the router when the edge agent has no inbound support like mobile agents.
2. To unregister the router, use `HTTP DELETE /route/unregister` API.

## Steps for custom message handling
Prerequisite - There should be a [connection](#Steps-for-DIDExchange) between Alice and Bob.
1. On Alice agent, go to `HTTP POST /message/register-service` and register a "generic-invite" message service for type "https://didcomm.org/generic/1.0/message"
   and purpose "meeting, appointment and event" by using below input parameter.
   ```json
   {
     "name": "generic-invite",
     "purpose": [
       "meeting","appointment","event"
     ],
     "type": "https://didcomm.org/generic/1.0/message"
   }
   ```
2. You can verify this new message service in alice agent by going to `HTTP GET /message/services` endpoint.

3. To send a message to Alice, in Bob agent go to `HTTP POST /message/send` and send a meeting invite message of type "https://didcomm.org/generic/1.0/message" and purpose "meeting". Input argument will look like this,
   ```json
   {
   "connection_ID":"5975a122-efac-4d7a-9a43-569a68f2311f",
   "message_body":{
   "@id":"2d071d1c-a47d-40e5-a0b7-f8234231ba9e",
   "@type":"https://didcomm.org/generic/1.0/message",
   "~purpose":["meeting"],
   "message":"Hey, meet me today at 4PM",
   "sender":"Bob"}
   }
   ```
   Note: In above message, `Connection_ID` is sample connection id from existing [connection](#Steps-for-DIDExchange) with Alice. You can also use `their_did` instead of `connection_ID` in above message to select recipient of this message from you existing connections.

4. Since REST API doesn't have mail box feature to list incoming messages, you can go to Alice agent's [webhook](http://localhost:8083/checktopics) url to see the topic/message just received by alice agent.

5. To unregister already registered message service, in alice agent go to `HTTP POST /message/unregister-service` and unregister "generic-invite" service by using below input parameter.
   ```json
   {
     "name": "generic-invite"
   }
   ```
## Steps for HTTP over DIDComm message handling
Steps http over did comm message handling is same as [above](#steps-for-custom-message-handling), but you can use `HTTP POST /http-over-didcomm/register` to register http-over-didcomm message handlers.

## Steps for creating public DID using vdri endpoint
To create public DID use `HTTP POST /vdri/create-public-did` endpoint. 
For example, to create a "sidetree" public DID in alice agent, go to `HTTP POST /vdri/create-public-did` of alice agent and use below parameters.
```
    method : sidetree
    header : {"alg":"","kid":"","operation":"create"}
```

## How to create a did-connection through the out-of-band protocol?
1. Create an invitation (Alice).
    ```
    curl -X POST "https://localhost:8082/outofband/create-invitation" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"label\": \"Alice\"}"
    ```
    The response should be similar to the following:
    ```json
    {"invitation":{"@id":"ac0b7436-ce9e-4972-853c-6f434a2f76c0","@type":"https://didcomm.org/oob-invitation/1.0/invitation","label":"Alice","service":[{"ID":"aad685bb-81aa-4c2f-bbd1-403814b8df9a","Type":"did-communication","Priority":0,"RecipientKeys":["9Mdoqbz8HtRZKYmNpBDR56xM4Ji7fRmuCcpfVP1YnfH2"],"RoutingKeys":null,"ServiceEndpoint":"https://alice.aries.example.com:8081","Properties":null}],"protocols":["https://didcomm.org/didexchange/1.0"]}}
    ```
2. Accept an invitation (Bob).
    ```
    curl -X POST "https://localhost:9082/outofband/accept-invitation" -H  "accept: application/json" -H  "Content-Type: application/json" -d "{  \"invitation\": {\"@id\":\"ac0b7436-ce9e-4972-853c-6f434a2f76c0\",\"@type\":\"https://didcomm.org/oob-invitation/1.0/invitation\",\"label\":\"Alice\",\"service\":[{\"ID\":\"aad685bb-81aa-4c2f-bbd1-403814b8df9a\",\"Type\":\"did-communication\",\"Priority\":0,\"RecipientKeys\":[\"9Mdoqbz8HtRZKYmNpBDR56xM4Ji7fRmuCcpfVP1YnfH2\"],\"RoutingKeys\":null,\"ServiceEndpoint\":\"https://alice.aries.example.com:8081\",\"Properties\":null}],\"protocols\":[\"https://didcomm.org/didexchange/1.0\"]},  \"my_label\": \"Bob\"}"
    ```
    The response should be similar to the following:
    ```json
    {"connection_id":"3ff80ad6-cfe8-4321-8a79-35da25437b48"}
    ```
3. Get connections with state equal to requested (Alice).
    ```
    curl -X GET "https://localhost:8082/connections?state=requested" -H  "accept: application/json"
    ```
    The response should be similar to the following:
    ```json
    {"results":[{"ConnectionID":"ea0a0545-d223-4ab0-9fdb-c01172a334f6","State":"requested","ThreadID":"7fa6e1d0-7d63-46cf-981c-729f937b1325","ParentThreadID":"","TheirLabel":"Bob","TheirDID":"did:peer:1zQmYHfqzguZfDPyTbF7UJyPndJn3XmeZ8hHzH7BTeC9DZG9","MyDID":"","ServiceEndPoint":"","RecipientKeys":null,"RoutingKeys":null,"InvitationID":"ac0b7436-ce9e-4972-853c-6f434a2f76c0","InvitationDID":"","Implicit":false,"Namespace":"their"}]}
    ```
4. Accept a request (Alice).
    ```
    curl -X POST "https://localhost:8082/connections/ea0a0545-d223-4ab0-9fdb-c01172a334f6/accept-request" -H  "accept: application/json" -d ""
    ```
    The response should be similar to the following:
    ```json
    {"their_did":"","request_id":"","connection_id":"ea0a0545-d223-4ab0-9fdb-c01172a334f6","updated_at":"0001-01-01T00:00:00Z","created_at":"0001-01-01T00:00:00Z","state":""}
    ```
5. Check whether the connection state is equal to completed (Alice).
    ```
    curl -X GET "https://localhost:8082/connections/ea0a0545-d223-4ab0-9fdb-c01172a334f6" -H  "accept: application/json"
    ```
    The response should be similar to the following:
    ```json
    {"result":{"ConnectionID":"ea0a0545-d223-4ab0-9fdb-c01172a334f6","State":"completed","ThreadID":"7fa6e1d0-7d63-46cf-981c-729f937b1325","ParentThreadID":"","TheirLabel":"Bob","TheirDID":"did:peer:1zQmYHfqzguZfDPyTbF7UJyPndJn3XmeZ8hHzH7BTeC9DZG9","MyDID":"did:peer:1zQmd2e1XhViEQ1DLJYKwgA9VDp8v5yuR38aAUs9GwjuKTsh","ServiceEndPoint":"","RecipientKeys":null,"RoutingKeys":null,"InvitationID":"ac0b7436-ce9e-4972-853c-6f434a2f76c0","InvitationDID":"","Implicit":false,"Namespace":"their"}}
    ```
6. Check whether the connection state is equal to completed (Bob).
    ```
    curl -X GET "https://localhost:9082/connections/3ff80ad6-cfe8-4321-8a79-35da25437b48" -H  "accept: application/json"
    ```
    The response should be similar to the following:
    ```json
    {"result":{"ConnectionID":"3ff80ad6-cfe8-4321-8a79-35da25437b48","State":"completed","ThreadID":"7fa6e1d0-7d63-46cf-981c-729f937b1325","ParentThreadID":"ac0b7436-ce9e-4972-853c-6f434a2f76c0","TheirLabel":"Alice","TheirDID":"did:peer:1zQmd2e1XhViEQ1DLJYKwgA9VDp8v5yuR38aAUs9GwjuKTsh","MyDID":"did:peer:1zQmYHfqzguZfDPyTbF7UJyPndJn3XmeZ8hHzH7BTeC9DZG9","ServiceEndPoint":"https://alice.aries.example.com:8081","RecipientKeys":["9Mdoqbz8HtRZKYmNpBDR56xM4Ji7fRmuCcpfVP1YnfH2"],"RoutingKeys":null,"InvitationID":"7fa6e1d0-7d63-46cf-981c-729f937b1325","InvitationDID":"","Implicit":false,"Namespace":"my"}}
    ```
   
## Notes 
Following features are not supported at the moment in RestAPI.
1. Connection search using different criterion.
2. Reply to a message using `HTTP POST /message/reply`

## References 
### Invitation
```json
{ 
   "serviceEndpoint":"http://alice.aries.example.com:8081",
   "recipientKeys":[ 
      "e3xUwgT9Qjb8KamK3kmvfRfmFf6LdYZMC6SeeV2oUnV"
   ],
   "@id":"90c46677-27a0-41e1-a272-68eb15bb1984",
   "label":"alice-agent",
   "@type":"https://didcomm.org/didexchange/1.0/invitation"
}
```

### Connection by ID API Response
```json
{ 
   "result":{ 
      "ConnectionID":"d0d6b8b0-d0f7-4319-b3ef-671c9fa9f3a4",
      "State":"invited",
      "ThreadID":"a9c0cd4c-9edb-4ec5-b74d-7df524792fe7",
      "TheirLabel":"alice-agent",
      "ServiceEndPoint":"http://alice.aries.example.com:8081",
      "RecipientKeys":[ 
         "e3xUwgT9Qjb8KamK3kmvfRfmFf6LdYZMC6SeeV2oUnV"
      ],
      "InvitationID":"90c46677-27a0-41e1-a272-68eb15bb1984",
      "Namespace":"my"
   }
}
```

### Connections API Response
```json
{
   "results":[ 
      { 
         "ConnectionID":"d0d6b8b0-d0f7-4319-b3ef-671c9fa9f3a4",
         "State":"invited",
         "ThreadID":"a9c0cd4c-9edb-4ec5-b74d-7df524792fe7",
         "TheirLabel":"alice-agent",
         "TheirDID":"",
         "MyDID":"",
         "ServiceEndPoint":"http://alice.aries.example.com:8081",
         "RecipientKeys":[ 
            "e3xUwgT9Qjb8KamK3kmvfRfmFf6LdYZMC6SeeV2oUnV"
         ],
         "InvitationID":"90c46677-27a0-41e1-a272-68eb15bb1984",
         "Namespace":"my"
      }
   ]
}
```