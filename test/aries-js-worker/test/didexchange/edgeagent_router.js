/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {healthCheck, newAries} from "../common.js"
import {environment} from "../environment.js"

const routerHttpUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_HTTP_INBOUND_PORT}`
const routerWsUrl = `${environment.WS_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_WS_INBOUND_PORT}`
const routerControllerApiUrl = `${environment.HTTP_SCHEME}://${environment.ROUTER_HOST}:${environment.ROUTER_API_PORT}`

const routerConnPath = "/connections"
const routerCreateInvitationPath = `${routerControllerApiUrl}${routerConnPath}/create-invitation`

// did exchange
const completedState = "completed"

// util
async function routerHealthCheck(routerHttpUrl, routerWsUrl, routerControllerApiUrl) {
    await healthCheck(routerHttpUrl, 5000, "healthCheck timeout!")
    await healthCheck(routerWsUrl, 5000, "healthCheck timeout!")
    await healthCheck(routerControllerApiUrl, 5000, "healthCheck timeout!")
}

function validateInvitation(invitation) {
    assert.isObject(invitation)
    assert.property(invitation, "serviceEndpoint")
    assert.property(invitation, "recipientKeys")
    assert.property(invitation, "@id")
    assert.property(invitation, "label")
    assert.property(invitation, "@type")
    assert.equal(invitation["@type"], "https://didcomm.org/didexchange/1.0/invitation")
}

function acceptInvitation(agent, invitation, done) {
    agent.startNotifier(notice => {
        try {
            assert.isFalse(notice.isErr)
            assert.property(notice, "payload")
            const connection = notice.payload
            assert.property(connection, "connection_id")
            agent.didexchange.acceptInvitation({
                id: connection.connection_id
            })
        } catch (err) {
            done(err)
        }
        done()
    }, ["connections"])
    agent.didexchange.receiveInvitation(invitation)
}

function routeRegister(agent, connectionID, done) {
    agent.router.register({
        "connectionID": connectionID
    }).then(
        resp => done(),
        err => done(err)
    )
}

function validateRouterConnection(agent, connectionID, done) {
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

// scenarios
describe("DID-Exchange between an Edge Agent and a router", function () {
    var aries
    var invitation

    before(async () => {
        return new Promise((resolve, reject) => {
            newAries().then(
                a => {
                    aries = a;
                    resolve()
                },
                err => reject(new Error(err.message))
            )
        })
    })

    after(() => {
        aries.destroy()
    })

    it(`Router is running on "${routerHttpUrl},${routerWsUrl}" with controller "${routerControllerApiUrl}"`, async function () {
        await routerHealthCheck(routerHttpUrl, routerWsUrl, routerControllerApiUrl)
    })

    it("Edge Agent receives an invitation from the router via the controller API", async function () {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation

        validateInvitation(invitation)
    })

    it("Edge Agent accepts the invitation from the router", function (done) {
        acceptInvitation(aries, invitation, done)
    })

    it("Edge Agent validates that the connection's state is 'completed'", function (done) {
        aries.startNotifier(notice => {
            try {
                assert.isObject(notice)
                assert.property(notice, "isErr")
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                assert.property(notice.payload, "state")
            } catch (err) {
                done(err)
            }
            if (notice.payload.state === completedState) {
                done()
            }
        }, ["connections"])
    })
})

describe("DID-Exchange between two Edge Agents using the router", function () {
    var aliceAgent, bobAgent
    var invitation, connectionID

    before(async () => {
        await newAries('alice')
            .then(a => {aliceAgent = a})
            .catch(err => new Error(err.message));

        await newAries('bob')
            .then(a => { bobAgent = a})
            .catch(err => new Error(err.message));
    })

    after(() => {
        aliceAgent.destroy()
        bobAgent.destroy()
    })

    it(`Router is running on "${routerHttpUrl},${routerWsUrl}" with controller "${routerControllerApiUrl}"`, async function () {
        await routerHealthCheck(routerHttpUrl, routerWsUrl, routerControllerApiUrl)
    })

    it("Alice Edge Agent receives an invitation from the router via the controller API", async function () {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation

        validateInvitation(invitation)
    })

    it("Alice Edge Agent accepts the invitation from the router", function (done) {
        acceptInvitation(aliceAgent, invitation, done)
    })

    it("Alice Edge Agent validates that the connection's state is 'completed'", function (done) {
        aliceAgent.startNotifier(notice => {
            try {
                assert.isObject(notice)
                assert.property(notice, "isErr")
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                assert.property(notice.payload, "state")
            } catch (err) {
                done(err)
            }
            if (notice.payload.state === completedState) {
                connectionID = notice.payload.connection_id

                done()
            }
        }, ["connections"])
    })

    it("Alice Edge Agent sets previous connection as the router", function (done) {
        routeRegister(aliceAgent, connectionID, done)
    })

    it("Alice Edge Agent validates that the router connection is set previous connection", function (done) {
        validateRouterConnection(aliceAgent, connectionID, done)
    })

    it("Bob Edge Agent receives an invitation from the router via the controller API", async function () {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation

        validateInvitation(invitation)
    })

    it("Bob Edge Agent accepts the invitation from the router", function (done) {
        acceptInvitation(bobAgent, invitation, done)
    })

    it("Bob Edge Agent validates that the connection's state is 'completed'", function (done) {
        bobAgent.startNotifier(notice => {
            try {
                assert.isObject(notice)
                assert.property(notice, "isErr")
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                assert.property(notice.payload, "state")
            } catch (err) {
                done(err)
            }
            if (notice.payload.state === completedState) {
                connectionID = notice.payload.connection_id

                done()
            }
        }, ["connections"])
    })

    it("Bob Edge Agent sets previous connection as the router", function (done) {
        routeRegister(bobAgent, connectionID, done)
    })

    it("Bob Edge Agent validates that the router connection is set previous connection", function (done) {
        validateRouterConnection(bobAgent, connectionID, done)
    })

    it("Alice Edge Agent receives an invitation from Bob Edge agent", function (done) {
        bobAgent.didexchange.createInvitation().then(
            resp => {
                invitation = resp.invitation
                validateInvitation(invitation)

                done()
            },
            err => done(err)
        )

        // bob approves all the requests
        bobAgent.startNotifier(notice => {
            try {
                assert.isObject(notice)
                assert.property(notice, "isErr")
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                assert.property(notice.payload, "state")

                if (notice.payload.state === "requested") {
                    const connection = notice.payload
                    bobAgent.didexchange.acceptExchangeRequest({
                        id: connection.connection_id
                    })
                }

            } catch (err) {
                done(err)
            }
        }, ["connections"])
    })

    it("Alice Edge Agent accepts the invitation from the Bob", function (done) {
        acceptInvitation(aliceAgent, invitation, done)
    })

    it("Alice Edge Agent validates that the connection's state is 'completed'", function (done) {
        aliceAgent.startNotifier(notice => {
            try {
                assert.isObject(notice)
                assert.property(notice, "isErr")
                assert.isFalse(notice.isErr)
                assert.property(notice, "payload")
                assert.property(notice.payload, "state")
            } catch (err) {
                done(err)
            }
            if (notice.payload.state === completedState) {
                done()
            }
        }, ["connections"])
    })
})

