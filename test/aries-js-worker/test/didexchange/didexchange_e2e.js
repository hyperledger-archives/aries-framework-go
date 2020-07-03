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

    constructor(agent1, agent2,mode) {
        this.agent1 = agent1
        this.agent2 = agent2
        this.mode = mode
    }

    async performDIDExchangeE2E() {
        if (this.mode === wasmMode) {
            await this.setupRouter()
        }

        // perform did exchange between agent 1 and agent 2
        // create invitation from agent1
        let response = await this.agent1.didexchange.createInvitation()
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
            didExchangeClient.acceptExchangeRequest(this.agent1, response.invitation['@id'])
        }

        // accept invitation in agent 2 and accept exchange request in agent 1
        await didExchangeClient.acceptInvitation(this.mode, this.agent2, response.invitation)

        return await connections
    }

    static async addRouter(mode, agent) {
        await agent.mediator.unregister().catch((err) => {
            if (!err.message.includes("router not registered")) {
                throw new Error(err)
            }
        })
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
    }

    async setupRouter() {
        this.hasMediator = true;
        await didExchangeClient.addRouter(this.mode, this.agent1)
        await didExchangeClient.addRouter(this.mode, this.agent2)
    }

    async destroy(){
        if (this.hasMediator){
            await this.agent1.mediator.unregister()
            await this.agent2.mediator.unregister()
        }

        this.agent1.destroy()
        this.agent2.destroy()
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

    static async acceptInvitation(mode, agent, invitation) {
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
            id: (await event).Properties.connectionID
        })
    }

    static acceptExchangeRequest(agent, messageID) {
        let options = {
            stateID: states.requested,
            type: postState,
            topic: statesTopic,
        }

        if (messageID) {
            options.messageID = messageID
        }

        return watchForEvent(agent, options).then((e) => {
            return agent.didexchange.acceptExchangeRequest({
                id: e.Properties.connectionID
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
        let resp = await agent.mediator.getConnection()
        assert.equal(resp.connectionID, connectionID)
    }
}

export async function newDIDExchangeClient(agent1, agent2) {
    let aries1, aries2;

    const init = (values) => {
        aries1 = values[0]
        aries2 = values[1]
    };

    await Promise.all([newAries(agent1,agent1), newAries(agent2,agent2)]).then(init).catch(err => new Error(err.message));

    return new didExchangeClient(aries1, aries2, wasmMode)
}


export async function newDIDExchangeRESTClient(agentURL1, agentURL2) {
    let aries1, aries2;

    const init = (values) => {
        aries1 = values[0]
        aries2 = values[1]
    };

    await Promise.all([newAriesREST(agentURL1), newAriesREST(agentURL2)]).then(init).catch(err => new Error(err.message));

    return new didExchangeClient(aries1, aries2, restMode)
}
