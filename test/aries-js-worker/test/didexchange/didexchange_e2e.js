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

    done(err) {
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

    async performDIDExchangeE2EWASM() {
        this.hasMediator = true;
        // receive an invitation from the router via the controller API
        var invitation = await this.createInvitationFromRouter(routerCreateInvitationPath)
        // agent1 accepts the invitation from the router
        await this.acceptInvitation(this.agent1, invitation, this.done)
        // wait for connection state for agent1 to be completed and get connection ID
        var connectionID = await this.watchForConnection(this.agent1, states.completed)
        // register with router
        await this.registerRouter(this.agent1, connectionID, this.done)
        //validate connection
        this.validateRouterConnection(this.agent1, connectionID, this.done)

        // receive an invitation from the router via the controller API
        invitation = await this.createInvitationFromRouter(routerCreateInvitationPath)
        // agent2 accepts the invitation from the router
        await this.acceptInvitation(this.agent2, invitation, this.done)
        // wait for connection state for agent2 to be completed and get connection ID
        connectionID = await this.watchForConnection(this.agent2, states.completed)
        // register with router
        await this.registerRouter(this.agent2, connectionID, this.done)
        //validate connection
        this.validateRouterConnection(this.agent2, connectionID, this.done)

        // perform did exchange between agent 1 and agent 2
        // create invitation from agent1
        let response = await this.agent1.didexchange.createInvitation()
        this.validateInvitation(response.invitation)
        // accept invitation in agent 2 and accept exchange request in agent 1
        await this.acceptInvitation(this.agent2, response.invitation, this.done)
        await this.acceptExchangeRequest(this.agent1)
        // wait for connection 'completed' in both the agents
        return await Promise.all([this.watchForConnection(this.agent1, states.completed), this.watchForConnection(this.agent2, states.completed)])
    }

    async performDIDExchangeE2EREST() {
        var response = await this.agent1.didexchange.createInvitation()
        this.validateInvitation(response.invitation)
        // accept invitation in agent 2
        this.acceptInvitation(this.agent2, response.invitation)
        // wait for connection 'completed' in both the agents
        return await Promise.all([this.watchForConnection(this.agent1, states.completed), this.watchForConnection(this.agent2, states.completed)])
    }

    async destroy(){
        if (this.hasMediator){
            await this.agent1.mediator.unregister()
            await this.agent2.mediator.unregister()
        }

        this.agent1.destroy()
        this.agent2.destroy()
    }

    async createInvitationFromRouter(endpoint) {
        const response = await axios.post(routerCreateInvitationPath)
        const invitation = response.data.invitation

        this.validateInvitation(invitation)

        return invitation
    }

    validateInvitation(invitation) {
        assert.isObject(invitation)
        assert.property(invitation, "serviceEndpoint")
        assert.property(invitation, "recipientKeys")
        assert.property(invitation, "@id")
        assert.property(invitation, "label")
        assert.property(invitation, "@type")
        assert.equal(invitation["@type"], "https://didcomm.org/didexchange/1.0/invitation")
    }

    async acceptInvitation(agent, invitation) {
        if (this.mode === restMode) {
            return agent.didexchange.receiveInvitation(invitation)
        }

        await agent.didexchange.receiveInvitation(invitation)

        let conn = await this.watchForConnection(agent, "invited")
        return agent.didexchange.acceptInvitation({
            id: conn
        })
    }

    async acceptExchangeRequest(agent){
        const connectionID = await this.watchForConnection(agent, states.requested)
        agent.didexchange.acceptExchangeRequest({
            id: connectionID
        })
    }

    watchForConnection(agent, state) {
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
            }, ["all"])
        })
    }

    async registerRouter(agent, connectionID) {
        await agent.mediator.register({"connectionID": connectionID})
    }

    validateRouterConnection(agent, connectionID, done) {
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
