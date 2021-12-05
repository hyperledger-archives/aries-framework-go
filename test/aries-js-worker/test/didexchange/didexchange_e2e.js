/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST, watchForEvent} from "../common.js"
import {environment} from "../environment.js"

const routerControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_API_PORT}`

const routerConnPath = "/connections"
const routerCreateInvitationPath = `${routerControllerApiUrl}${routerConnPath}/create-invitation`

const statesTopic = "didexchange_states"
const postState = "post_state"

// did exchange
const states = {
    completed: "completed",
    requested: "requested",
    invited: "invited",
}

const restMode = 'rest'
const wasmMode = 'wasm'

/**
 * DID exchange client for JS bdd tests
 * @param aries agent1 and agent2 instances
 * @class
 *
 */
export const didExchangeClient = class {
    hasMediator = false;

    constructor(agent1, agent2, mode) {
        this.agent1 = agent1
        this.agent2 = agent2
        this.mode = mode
        this.agent1RouterConnection = ""
        this.agent2RouterConnection = ""
    }

    async performDIDExchangeE2E() {
        if (this.mode === wasmMode) {
            await this.setupRouter()
        }

        // perform did exchange between agent 1 and agent 2
        // create invitation from agent1
        let response = await this.agent1.didexchange.createInvitation({
            router_connection_id: this.agent1RouterConnection
        })
        didExchangeClient.validateInvitation(response.invitation)

        // wait for connection 'completed' in both the agents
        const options = {
            stateID: states.completed,
            type: postState,
            topic: statesTopic,
            messageThreadID: response.invitation['@id'],
        }
        let connections = Promise.all([
            watchForEvent(this.agent1, options).then((e) => {
                return e.Properties.connectionID
            }),
            watchForEvent(this.agent2, options).then((e) => {
                return e.Properties.connectionID
            })
        ])

        if (this.mode === wasmMode) {
            didExchangeClient.acceptExchangeRequest(this.agent1, response.invitation['@id'], this.agent1RouterConnection)
        }

        // accept invitation in agent 2 and accept exchange request in agent 1
        await didExchangeClient.acceptInvitation(this.mode, this.agent2,
            response.invitation, this.agent2RouterConnection)

        return await connections
    }

    async createDIDCommV2Connection() {
        let connections = await this.performDIDExchangeE2E()

        let setToV2Resp = await Promise.all([
            this.agent1.connection.SetConnectionToDIDCommV2({id: connections[0]}),
            this.agent2.connection.SetConnectionToDIDCommV2({id: connections[1]})
        ])

        assert.isNotEmpty(setToV2Resp);

        return connections
    }

    static async addRouter(mode, agent) {
        try {
            let resp = await agent.mediator.getConnections()
            if (resp.connections){
                for (let i = 0; i < resp.connections.length; i++) {
                    await agent.mediator.unregister({"connectionID": resp.connections[i]})
                }
            }
        }catch (e){
            if (!e.message.includes("data not found")) {
                throw new Error(e);
            }

            console.log(e)
        }

        // receive an invitation from the router via the controller API
        let invitation = await didExchangeClient.createInvitationFromRouter(routerCreateInvitationPath)
        // agent1 accepts the invitation from the router
        await didExchangeClient.acceptInvitation(mode, agent, invitation)
        // wait for connection state for agent to be completed and get connection ID
        let event = await watchForEvent(agent, {
            stateID: states.completed,
            type: postState,
            topic: statesTopic,
            messageThreadID: invitation['@id'],
        })

        // register with router
        await didExchangeClient.registerRouter(agent, event.Properties.connectionID).catch((err) => {
            if (!err.message.includes("router is already registered")) {
                throw new Error(err)
            }
        })
        //validate connection
        await didExchangeClient.validateRouterConnection(agent, event.Properties.connectionID)

        return event.Properties.connectionID
    }

    async setupRouter() {
        this.hasMediator = true;
        this.agent1RouterConnection = await didExchangeClient.addRouter(this.mode, this.agent1)
        this.agent2RouterConnection = await didExchangeClient.addRouter(this.mode, this.agent2)
    }

    async destroy() {
        if (this.hasMediator) {
            await this.agent1.mediator.unregister({"connectionID": this.agent1RouterConnection})
            await this.agent2.mediator.unregister({"connectionID": this.agent2RouterConnection})
        }

        this.agent1 ? await this.agent1.destroy() : ''
        this.agent2 ?  await this.agent2.destroy() : ''
    }

    static async createInvitationFromRouter(endpoint) {
        const response = await axios.post(routerCreateInvitationPath)
        const invitation = response.data.invitation

        didExchangeClient.validateInvitation(invitation)

        return invitation
    }

    static validateInvitation(invitation) {
        assert.isObject(invitation)
        assert.property(invitation, "serviceEndpoint")
        assert.property(invitation, "recipientKeys")
        assert.property(invitation, "@id")
        assert.property(invitation, "label")
        assert.property(invitation, "@type")
        assert.equal(invitation["@type"], "https://didcomm.org/didexchange/1.0/invitation")
    }

    static async acceptInvitation(mode, agent, invitation, router = "") {
        if (mode === restMode) {
            return agent.didexchange.receiveInvitation(invitation)
        }

        let event = watchForEvent(agent, {
            stateID: states.invited,
            type: postState,
            topic: statesTopic,
            messageID: invitation['@id'],
        })

        await agent.didexchange.receiveInvitation(invitation)

        return agent.didexchange.acceptInvitation({
            id: (await event).Properties.connectionID,
            router_connections: router,
        })
    }

    static acceptExchangeRequest(agent, messageID, router = "") {
        let options = {
            stateID: states.requested,
            type: postState,
            topic: statesTopic,
        }

        if (messageID) {
            options.messageID = messageID
        }

        return watchForEvent(agent, options).then(async (e) => {
            return agent.didexchange.acceptExchangeRequest({
                id: e.Properties.connectionID,
                router_connections: router,
            })
        })
    }

    static watchForConnection(agent, state) {
        return watchForEvent(agent, {
            stateID: state,
            type: postState,
            topic: statesTopic,
        }).then((e) => {
            return e.Properties.connectionID
        }).catch(e => {
            throw new Error(e)
        })
    }

    static async registerRouter(agent, connectionID) {
        await agent.mediator.register({"connectionID": connectionID})
    }

    static async validateRouterConnection(agent, connectionID) {
        let resp = await agent.mediator.getConnections()
        assert.isTrue(resp.connections.includes(connectionID))
    }
}

export async function newDIDExchangeClient(agent1, agent2) {
    let aries1 = await newAries(agent1, agent1, [], [`${environment.HTTP_LOCAL_CONTEXT_PROVIDER_URL}`], [`${environment.USER_MEDIA_TYPE_PROFILES}`])
    let aries2 = await newAries(agent2, agent2, [], [`${environment.HTTP_LOCAL_CONTEXT_PROVIDER_URL}`], [`${environment.USER_MEDIA_TYPE_PROFILES}`])

    return new didExchangeClient(aries1, aries2, wasmMode)
}


export async function newDIDExchangeRESTClient(agentURL1, agentURL2) {
    let aries1 = await newAriesREST(agentURL1, [`${environment.USER_MEDIA_TYPE_PROFILES}`])
    let aries2 = await newAriesREST(agentURL2, [`${environment.USER_MEDIA_TYPE_PROFILES}`])

    return new didExchangeClient(aries1, aries2, restMode)
}
