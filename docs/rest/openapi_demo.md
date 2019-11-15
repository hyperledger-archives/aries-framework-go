# Run OpenAPI demo

## Setup
Launch the demo by running the following make target from project root directory.

`make run-openapi-demo`

Once both agents are up, click on the agent specific urls to launch the OpenAPI interface.

[Alice OpenAPI Interface](http://localhost:8089/openapi/)

[Bob OpenAPI Interface](http://localhost:9089/openapi/)

## Steps  
1. On Alice agent, generate an invitation with `HTTP POST /connections/create-invitation` and copy the invitation from the response. Refer [here](#Invitation) for sample invitation json. 
2. On Bob agent, save the invitation received from Alice with `HTTP POST /connections/receive-invitation` API. Note down the connection ID generated in the response.
3. `HTTP GET /connections/{id}` with the connection ID from the previous step fetches the new connection record. The state of this record should be `invited`. Refer [here](#Connection-by-ID-API-Response) for sample response. 
4. Also, `HTTP GET /connections` fetches all connection records. There should be one connection with state "invited". Refer [here](#Connections-API-Response) for sample response.
5. On Bob agent, accept the Invitation from Alice by sending connection ID with `HTTP POST /connections/{id}/accept-invitation`. After this, the state of the connection should be updated to `requested`.
6. On Alice agent, fetch all connections with `HTTP GET /connections`. There will be one record with status `requested` (request from Bob). Get the connection ID of this record.
7. On Alice agent, accept the Bob's request with `HTTP POST /connections/{id}/accept-request` API. 
8. Calling `HTTP GET /connections/{id}` on both agents should show the connections with state `completed`. Alice and Bob are now connected.

## Notes 
Following features are not supported at the moment in RestAPI.
1. Connection search using different criterion.

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