# Run OpenAPI demo

## Setup
Launch the demo by running the following make target from project root directory.

`make run-openapi-demo`

Once both agents are up, click on the agent specific urls to launch the OpenAPI interface.

[Alice OpenAPI Interface](http://localhost:8089/openapi/)

[Bob OpenAPI Interface](http://localhost:9089/openapi/)

## Steps  
1. On Alice agent, generate an invitation by invoking `/connections/create-invitation` API and copy the invitation from the response. Refer [here](#Invitation) for sample invitation json. 
2. On Bob agent, save the invitation received from Alice using `/connections/receive-invitation` API. Note down the connection ID generated in the response.
3. Call `/connections/{id}` API with the connection ID copied in previous step to see the connection record. The state of this record should be `invited`. Refer [here](#Connection-by-ID-API-Response) for sample response. 
4. Also, the `/connections/` API can be used to get all the connection record. There should be one connection with state "invited". Refer [here](#Connections-API-Response) for sample response.
5. Accept the Invitation from Alice by sending connection ID in `/connections/accept-invitation` API. After this, the state of the connection should be updated to `requested`.
6. On Alice agent, invoke `/connections/` API get all the connections. There will be one record with status `requested` (request from Bob). Get the connection ID of this record.
7. Accept the Request from Bob by sending connection ID in `/connections/accept-request` API. 
8. The state of the connection should be `completed` for both Alice and Bob.

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