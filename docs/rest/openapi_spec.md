# Generate OpenAPI spec

## Setup
Controller REST API specifications are generated according to Open API 2.0 standards.
All the models and handle functions to be part of controller API which are inside package `pkg/restapi` are annotated according to Open API 2.0 standards.

Controller REST API spec can be generated using those annotations by running following make target from project root directory. 

`make generate-openapi-spec`

Generated spec can be found under `build/rest/openapi/spec/openAPI.yml` 

Sample specification can be found [here](#Controller REST API Specification)

## References 
### Controller REST API Specification
```
consumes:
- application/json
definitions:
  Connection:
    description: This is used to represent query connection result
    properties:
      ConnectionID:
        type: string
      InvitationID:
        type: string
      MyDID:
        type: string
      Namespace:
        type: string
      RecipientKeys:
        items:
          type: string
        type: array
      ServiceEndPoint:
        type: string
      State:
        type: string
      TheirDID:
        type: string
      TheirLabel:
        type: string
      ThreadID:
        type: string
    title: Connection model
    type: object
    x-go-package: github.com/hyperledger/aries-framework-go/pkg/client/didexchange
  ExchangeResponse:
    description: response of accept exchange request
    properties:
      accept:
        description: Connection invitation accept mode
        type: string
        x-go-name: Accept
      alias:
        description: Alias of connection invitation
        type: string
        x-go-name: Alias
      connection_id:
        description: the connection ID of the connection invitation
        type: string
        x-go-name: ConnectionID
      created_at:
        description: Created time
        format: date-time
        type: string
        x-go-name: CreatedTime
      error_msg:
        description: Error message
        type: string
        x-go-name: Error
      inbound_connection_id:
        description: the connection ID of the connection invitation
        type: string
        x-go-name: InboundConnectionID
      initiator:
        description: Initiator is Connection invitation initiator
        type: string
        x-go-name: Initiator
      invitation_key:
        description: Invitation key
        type: string
        x-go-name: InvitationKey
      invitation_mode:
        description: Invitation mode
        type: string
        x-go-name: Mode
      my_did:
        description: MyDID is DID of the agent
        type: string
        x-go-name: MyDID
      request_id:
        description: Request ID of the connection request
        type: string
        x-go-name: RequestID
      routing_state:
        description: Routing state of connection invitation
        type: string
        x-go-name: RoutingState
      state:
        description: State of the connection invitation
        type: string
        x-go-name: State
      their_did:
        description: TheirDID is other party's DID
        type: string
        x-go-name: TheirDID
      their_label:
        description: TheirRole is other party's role
        type: string
        x-go-name: TheirLabel
      their_role:
        description: TheirRole is other party's role
        type: string
        x-go-name: TheirRole
      updated_at:
        description: Updated time
        format: date-time
        type: string
        x-go-name: UpdatedTime
    title: ExchangeResponse model
    type: object
    x-go-package: github.com/hyperledger/aries-framework-go/pkg/restapi/operation/didexchange/models
  Invitation:
    properties:
      '@id':
        description: the ID of the connection invitation
        type: string
        x-go-name: ID
      '@type':
        description: the Type of the connection invitation
        type: string
        x-go-name: Type
      did:
        description: the DID of the connection invitation
        type: string
        x-go-name: DID
      imageUrl:
        description: the Image URL of the connection invitation
        type: string
        x-go-name: ImageURL
      label:
        description: the Label of the connection invitation
        type: string
        x-go-name: Label
      recipientKeys:
        description: the RecipientKeys for the connection invitation
        items:
          type: string
        type: array
        x-go-name: RecipientKeys
      routingKeys:
        description: the RoutingKeys of the connection invitation
        items:
          type: string
        type: array
        x-go-name: RoutingKeys
      serviceEndpoint:
        description: the Service endpoint of the connection invitation
        type: string
        x-go-name: ServiceEndpoint
    title: Invitation model for DID Exchange invitation.
    type: object
    x-go-package: github.com/hyperledger/aries-framework-go/pkg/client/didexchange
info:
  license:
    name: 'SPDX-License-Identifier: Apache-2.0'
  title: (Aries Agent Server) of aries-framework-go.
  version: 0.1.0
paths:
  /connections:
    get:
      operationId: queryConnections
      parameters:
      - description: Alias of connection invitation
        in: query
        name: alias
        type: string
        x-go-name: Alias
      - description: Initiator is Connection invitation initiator
        in: query
        name: initiator
        type: string
        x-go-name: Initiator
      - description: Invitation key
        in: query
        name: invitation_key
        type: string
        x-go-name: InvitationKey
      - description: MyDID is DID of the agent
        in: query
        name: my_did
        type: string
        x-go-name: MyDID
      - description: State of the connection invitation
        in: query
        name: state
        type: string
        x-go-name: State
      - description: TheirDID is other party's DID
        in: query
        name: their_did
        type: string
        x-go-name: TheirDID
      - description: TheirRole is other party's role
        in: query
        name: their_role
        type: string
        x-go-name: TheirRole
      responses:
        "200":
          $ref: '#/responses/queryConnectionsResponse'
        default:
          $ref: '#/responses/genericError'
      summary: query agent to agent connections.
      tags:
      - did-exchange
  /connections/{id}:
    get:
      operationId: getConnection
      parameters:
      - description: The ID of the connection to get
        in: path
        name: id
        required: true
        type: string
        x-go-name: ID
      responses:
        "200":
          $ref: '#/responses/queryConnectionResponse'
        default:
          $ref: '#/responses/genericError'
      summary: Fetch a single connection record.
      tags:
      - did-exchange
  /connections/{id}/accept-invitation:
    post:
      operationId: acceptInvitation
      parameters:
      - description: The ID of Invitation Request to accept
        in: path
        name: id
        required: true
        type: string
        x-go-name: ID
      responses:
        "200":
          $ref: '#/responses/acceptInvitationResponse'
        default:
          $ref: '#/responses/genericError'
      summary: Accept a stored connection invitation....
      tags:
      - did-exchange
  /connections/{id}/accept-request:
    post:
      operationId: acceptRequest
      parameters:
      - description: The ID of the connection request to accept
        in: path
        name: id
        required: true
        type: string
        x-go-name: ID
      responses:
        "200":
          $ref: '#/responses/acceptExchangeResponse'
        default:
          $ref: '#/responses/genericError'
      summary: Accepts a stored connection request.
      tags:
      - did-exchange
  /connections/{id}/remove:
    post:
      operationId: removeConnection
      parameters:
      - description: The ID of the connection record to remove
        in: path
        name: id
        required: true
        type: string
        x-go-name: ID
      responses:
        "200":
          $ref: '#/responses/removeConnectionResponse'
        default:
          $ref: '#/responses/genericError'
      summary: Removes given connection record.
      tags:
      - did-exchange
  /connections/create-invitation:
    post:
      operationId: createInvitation
      parameters:
      - description: The Alias to be used in invitation to be created
        in: query
        name: alias
        type: string
        x-go-name: Alias
      - description: The Public flag to create an invitation from the public DID
        in: query
        name: public
        type: boolean
        x-go-name: Public
      responses:
        "200":
          $ref: '#/responses/createInvitationResponse'
        default:
          $ref: '#/responses/genericError'
      summary: Creates a new connection invitation....
      tags:
      - did-exchange
  /connections/receive-invitation:
    post:
      operationId: receiveInvitation
      parameters:
      - description: The Invitation Request to receive
        in: body
        name: Invitation
        required: true
        schema:
          $ref: '#/definitions/Invitation'
      responses:
        "200":
          $ref: '#/responses/receiveInvitationResponse'
        default:
          $ref: '#/responses/genericError'
      summary: Receive a new connection invitation....
      tags:
      - did-exchange
produces:
- application/json
responses:
  acceptExchangeResponse:
    description: |-
      AcceptExchangeResult model

      This is used for returning response for accept exchange request
    schema:
      $ref: '#/definitions/ExchangeResponse'
  acceptInvitationResponse:
    description: |-
      AcceptInvitationResponse model

      This is used for returning a accept invitation response for single invitation
    headers:
      accept:
        description: Connection invitation accept mode
        type: string
      alias:
        description: Alias
        type: string
      connection_id:
        description: the connection ID of the connection invitation
        type: string
      created_at:
        description: Created time
        format: date-time
        type: string
      error_msg:
        description: Error message
        type: string
      inbound_connection_id:
        description: Inbound Connection ID  of the connection invitation
        type: string
      initiator:
        description: Connection invitation initiator
        type: string
      invitation_key:
        description: Invitation key
        type: string
      invitation_mode:
        description: Invitation mode
        type: string
      my_did:
        description: My DID
        type: string
      request_id:
        description: Request ID of invitation response
        type: string
      routing_state:
        description: Routing state of connection invitation
        type: string
      state:
        description: State of the connection invitation
        type: string
      their_did:
        description: Other party's DID
        type: string
      their_label:
        description: Other party's label
        type: string
      their_role:
        description: Other party's role
        type: string
      updated_at:
        description: Updated time
        format: date-time
        type: string
  createInvitationResponse:
    description: |-
      CreateInvitationResponse model

      This is used for returning a create invitation response with a single connection invitation as body
    schema:
      $ref: '#/definitions/Invitation'
  genericError:
    description: |-
      A GenericError is the default error message that is generated.
      For certain status codes there are more appropriate error structures.
    schema:
      properties:
        code:
          format: int32
          type: integer
          x-go-name: Code
        message:
          type: string
          x-go-name: Message
      type: object
  queryConnectionResponse:
    description: |-
      QueryConnectionResponse model

      This is used for returning query connection result for single record search
    schema:
      $ref: '#/definitions/Connection'
  queryConnectionsResponse:
    description: |-
      QueryConnectionsResponse model

      This is used for returning query connections results
    schema:
      items:
        $ref: '#/definitions/Connection'
      type: array
  receiveInvitationResponse:
    description: |-
      ReceiveInvitationResponse model

      This is used for returning a receive invitation response with a single receive invitation response as body
    headers:
      accept:
        description: Connection invitation accept mode
        type: string
      connection_id:
        description: the connection ID of the connection invitation
        type: string
      created_at:
        description: Created time
        format: date-time
        type: string
      initiator:
        description: Connection invitation initiator
        type: string
      invitation_key:
        description: Invitation key
        type: string
      invitation_mode:
        description: Invitation mode
        type: string
      my_did:
        description: My DID
        type: string
      request_id:
        description: Request ID of invitation response
        type: string
      routing_state:
        description: Routing state of connection invitation
        type: string
      state:
        description: State of the connection invitation
        type: string
      their_label:
        description: Other party's label
        type: string
      updated_at:
        description: Updated time
        format: date-time
        type: string
  removeConnectionResponse:
    description: |-
      RemoveConnectionResponse model

      response of remove connection action
schemes:
- http
- https
swagger: "2.0"

```
