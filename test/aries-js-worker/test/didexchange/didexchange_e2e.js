/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newAries, newAriesREST} from "../common.js"
import {environment} from "../environment.js"

const routerHttpUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_HTTP_INBOUND_PORT}`
const routerWsUrl = `${environment.WS_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_WS_INBOUND_PORT}`
const routerControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_API_PORT}`

const routerConnPath = "/connections"
const routerCreateInvitationPath = `${routerControllerApiUrl}${routerConnPath}/create-invitation`

// did exchange
const states = {
    completed: "completed",
    requested: "requested",
}

/**
 * DID exchange client for JS bdd tests
 * @param aries agent1 and agent2 instances
 * @class
 *
 */
export const didExchangeClient = class {
    constructor(agent1, agent2) {
        this.agent1 = agent1
        this.agent2 = agent2
    }

    done(err) {
        if (err) {
            throw new Error(err.message)
        }
    }

    async performDIDExchangeE2E() {
        let connectionIDs
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
        var response = await this.agent1.didexchange.createInvitation()
        this.validateInvitation(response.invitation)
       // accept invitation in agent 2 and accept exchange request in agent 1
        await Promise.all([this.acceptInvitation(this.agent2, response.invitation, this.done), await this.acceptExchangeRequest(this.agent1)]).then(
            values => {
                this.done()
            }
        ).catch(
            err => {
                this.done(err)
            }
        )
        // wait for connection 'completed' in both the agents
        await Promise.all([this.watchForConnection(this.agent1, states.completed), this.watchForConnection(this.agent2, states.completed)]).then(
            values => {
                this.done()
                connectionIDs = values
            }
        ).catch(
            err => {
                this.done(err)
            }
        )

        return connectionIDs
    }

    async destroy(){
        await this.agent1.router.unregister()
        await this.agent2.router.unregister()

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

    acceptInvitation(agent, invitation, done) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error("time out while accepting invitation")), 10000)
            const stop = agent.startNotifier(notice => {
                try {
                    assert.isFalse(notice.isErr)
                    assert.property(notice, "payload")
                    const connection = notice.payload
                    assert.property(connection, "connection_id")
                    agent.didexchange.acceptInvitation({
                        id: connection.connection_id
                    })
                    stop()
                    resolve(connection)
                } catch (err) {
                    reject(err)
                }
            }, ["connections"])
            agent.didexchange.receiveInvitation(invitation)
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

    async registerRouter(agent, connectionID, done) {
        var resp
        try {
        resp = await agent.router.register({
            "connectionID": connectionID
        })} catch(err) {
           done(err)
        }
    }

    validateRouterConnection(agent, connectionID, done) {
        agent.router.getConnection().then(
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

export async function newDIDExchangeClient(agent1, agent2, restmode) {
    let aries1, aries2;

    const init = (values) => {
        aries1 = values[0]
        aries2 = values[1]
    };

    await Promise.all([newAries(agent1,agent1), newAries(agent2,agent2)]).then(init).catch(err => new Error(err.message));

    return new didExchangeClient(aries1, aries2)
}


export async function newDIDExchangeRESTClient(agentURL1, agentURL2) {
    let aries1, aries2;

    const init = (values) => {
        aries1 = values[0]
        aries2 = values[1]
    };

    await Promise.all([newAriesREST(agentURL1), newAriesREST(agentURL2)]).then(init).catch(err => new Error(err.message));

    return new didExchangeClient(aries1, aries2)
}