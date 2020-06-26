/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js"

const routerControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_API_PORT}`

const routerConnPath = "/connections"
const routerCreateInvitationPath = `${routerControllerApiUrl}${routerConnPath}/create-invitation`

// did exchange
const states = {
    completed: "completed",
    requested: "requested",
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

    static done(err) {
        if (err) {
            throw new Error(err.message)
        }
    }

    async performDIDExchangeE2E() {
        if (this.mode === restMode){
            return await this.performDIDExchangeE2EREST()
        }

        return await this.performDIDExchangeE2EWASM()
    }

    static async addRouter(mode, agent) {
        // receive an invitation from the router via the controller API
        let invitation = await didExchangeClient.createInvitationFromRouter(routerCreateInvitationPath)
        // agent1 accepts the invitation from the router
        await didExchangeClient.acceptInvitation(mode, agent, invitation, didExchangeClient.done)
        // wait for connection state for agent to be completed and get connection ID
        let connectionID = await didExchangeClient.watchForConnection(agent, states.completed)
        // register with router
        await didExchangeClient.registerRouter(agent, connectionID, didExchangeClient.done).catch((err) => {
            if (!err.message.includes("router is already registered")) {
                throw new Error(err)
            }
        })
        //validate connection
        didExchangeClient.validateRouterConnection(agent, connectionID, didExchangeClient.done)
    }

    async setupRouter() {
        this.hasMediator = true;
        await didExchangeClient.addRouter(this.mode, this.agent1)
        await didExchangeClient.addRouter(this.mode, this.agent2)
    }

    async performDIDExchangeE2EWASM() {
        await this.setupRouter()

        // perform did exchange between agent 1 and agent 2
        // create invitation from agent1
        let response = await this.agent1.didexchange.createInvitation()
        didExchangeClient.validateInvitation(response.invitation)
        // accept invitation in agent 2 and accept exchange request in agent 1
        await didExchangeClient.acceptInvitation(this.mode, this.agent2, response.invitation, didExchangeClient.done)
        await didExchangeClient.acceptExchangeRequest(this.agent1)
        // wait for connection 'completed' in both the agents
        return await Promise.all([didExchangeClient.watchForConnection(this.agent1, states.completed), didExchangeClient.watchForConnection(this.agent2, states.completed)])
    }

    async performDIDExchangeE2EREST() {
        let response = await this.agent1.didexchange.createInvitation()
        didExchangeClient.validateInvitation(response.invitation)

        let connections = Promise.all([didExchangeClient.watchForConnection(this.agent1, states.completed), didExchangeClient.watchForConnection(this.agent2, states.completed)])
        // accept invitation in agent 2
        await didExchangeClient.acceptInvitation(this.mode, this.agent2, response.invitation)
        // wait for connection 'completed' in both the agents
        return await connections
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

        await agent.didexchange.receiveInvitation(invitation)

        return didExchangeClient.watchForConnection(agent, "invited").then((conn) => {
            agent.didexchange.acceptInvitation({
                id: conn
            })
        })
    }

    static acceptExchangeRequest(agent) {
        return didExchangeClient.watchForConnection(agent, states.requested).then(async (connectionID) => {
            await agent.didexchange.acceptExchangeRequest({
                id: connectionID
            })
        })
    }

    static watchForConnection(agent, state) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error("time out while waiting for connection")), 5000)
            const stop = agent.startNotifier(notice => {
                try {
                    assert.isObject(notice)
                    assert.property(notice, "isErr")
                    assert.isFalse(notice.isErr)
                    assert.property(notice, "payload")
                    assert.property(notice.payload, "state")
                    assert.isNotEmpty(notice.payload.connection_id)
                } catch (err) {
                    reject(err)
                }
                if (notice.payload.state === state) {
                    stop()
                    resolve(notice.payload.connection_id)
                }
            }, ["connections"])
        })
    }

    static async registerRouter(agent, connectionID) {
        await agent.mediator.register({"connectionID": connectionID})
    }

    static validateRouterConnection(agent, connectionID, done) {
        agent.mediator.getConnection().then(
            resp => {
                try {
                    assert.equal(resp.connectionID, connectionID)
                } catch (err) {
                    done(err)
                }

                done()
            },
            err => done(err)
        )
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
