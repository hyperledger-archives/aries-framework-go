/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {healthCheck, newAries} from "../common.js"
import {environment} from "../environment.js"
import {didExchangeClient} from "../didexchange/didexchange_e2e.js";

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

function routeRegister(agent, connectionID, done) {
    agent.mediator.register({
        "connectionID": connectionID
    }).then(
        resp => done(),
        err => done(err)
    )
}

function validateRouterConnection(agent, connectionID, done) {
    agent.mediator.getConnections().then(
        resp => {
            try {
                assert.isTrue(resp.connections.includes(connectionID))
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
    let aries
    let invitation

    before(async () => {
        return new Promise((resolve, reject) => {
            newAries(null, null, null, null, [`${environment.USER_MEDIA_TYPE_PROFILES}`]).then(
                a => {
                    aries = a;
                    resolve()
                },
                err => reject(new Error(err.message))
            )
        })
    })

    after(async () => {
       await aries.destroy()
    })

    it(`Router is running on "${routerHttpUrl},${routerWsUrl}" with controller "${routerControllerApiUrl}"`, async function () {
        await routerHealthCheck(routerHttpUrl, routerWsUrl, routerControllerApiUrl)
    })

    it("Edge Agent receives an invitation from the router via the controller API", async function () {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation

        validateInvitation(invitation)
    })

    it("Edge Agent accepts the invitation from the router", async function () {
        await didExchangeClient.acceptInvitation('wasm', aries, invitation)
    })

    it("Edge Agent validates that the connection's state is 'completed'", async function () {
        await didExchangeClient.watchForConnection(aries, completedState)
    })
})

describe("DID-Exchange between two Edge Agents using the router", function () {
    let aliceAgent, bobAgent
    let invitation, aliceConnectionID, bobConnectionID

    before(async () => {
        aliceAgent = await newAries('alice')
        bobAgent = await newAries('bob')
    })

    after(async() => {
        await aliceAgent.destroy()
        await bobAgent.destroy()
    })

    it(`Router is running on "${routerHttpUrl},${routerWsUrl}" with controller "${routerControllerApiUrl}"`, async function () {
        await routerHealthCheck(routerHttpUrl, routerWsUrl, routerControllerApiUrl)
    })

    it("Alice Edge Agent receives an invitation from the router via the controller API", async function () {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation

        validateInvitation(invitation)
    })

    it("Alice Edge Agent accepts the invitation from the router", async function () {
        let res = await didExchangeClient.acceptInvitation('wasm', aliceAgent, invitation)
        aliceConnectionID = res.connection_id
    })

    it("Alice Edge Agent validates that the connection's state is 'completed'", async function () {
        let connID = await didExchangeClient.watchForConnection(aliceAgent, completedState)
        assert.equal(aliceConnectionID, connID)
    })

    it("Alice Edge Agent sets previous connection as the router", function (done) {
        routeRegister(aliceAgent, aliceConnectionID, done)
    })

    it("Alice Edge Agent validates that the router connection is set previous connection", function (done) {
        validateRouterConnection(aliceAgent, aliceConnectionID, done)
    })

    it("Bob Edge Agent receives an invitation from the router via the controller API", async function () {
        const response = await axios.post(routerCreateInvitationPath)
        invitation = response.data.invitation

        validateInvitation(invitation)
    })

    it("Bob Edge Agent accepts the invitation from the router",async function () {
        let res = await didExchangeClient.acceptInvitation('wasm', bobAgent, invitation)
        bobConnectionID = res.connection_id
    })

    it("Bob Edge Agent validates that the connection's state is 'completed'",async function () {
        let connID = await didExchangeClient.watchForConnection(bobAgent, completedState)
        assert.equal(bobConnectionID, connID)
    })

    it("Bob Edge Agent sets previous connection as the router", function (done) {
        routeRegister(bobAgent, bobConnectionID, done)
    })

    it("Bob Edge Agent validates that the router connection is set previous connection", function (done) {
        validateRouterConnection(bobAgent, bobConnectionID, done)
    })

    it("Alice Edge Agent receives an invitation from Bob Edge agent", function (done) {
        didExchangeClient.acceptExchangeRequest(bobAgent, "", bobConnectionID)

        bobAgent.didexchange.createInvitation({router_connection_id: bobConnectionID}).then(
            resp => {
                invitation = resp.invitation
                validateInvitation(invitation)
                done()
            },
            err => done(err)
        )
    })

    it("Alice Edge Agent accepts the invitation from the Bob", async function () {
        await didExchangeClient.acceptInvitation('wasm', aliceAgent, invitation, aliceConnectionID)
    })

    it("Alice Edge Agent validates that the connection's state is 'completed'", async function () {
        await didExchangeClient.watchForConnection(aliceAgent, completedState)
    })
})

describe("Registers multiple routers", function () {
    let aliceAgent
    let invitation1, connectionID1, invitation2, connectionID2

    before(async () => {
        aliceAgent = await newAries('alice')
    })

    after(async () => {
        await aliceAgent.destroy()
    })

    it(`Router is running on "${routerHttpUrl},${routerWsUrl}" with controller "${routerControllerApiUrl}"`, async function () {
        await routerHealthCheck(routerHttpUrl, routerWsUrl, routerControllerApiUrl)
    })

    it("Alice Edge Agent receives invitations from the router via the controller API", async function () {
        const inv1 = await axios.post(routerCreateInvitationPath)
        invitation1 = inv1.data.invitation
        validateInvitation(invitation1)

        const inv2 = await axios.post(routerCreateInvitationPath)
        invitation2 = inv2.data.invitation

        validateInvitation(invitation2)
    })

    it("Alice Edge Agent accepts the invitation(first) from the router", async function () {
        let res = await didExchangeClient.acceptInvitation('wasm', aliceAgent, invitation1)
        let connID = await didExchangeClient.watchForConnection(aliceAgent, completedState)
        connectionID1 = res.connection_id
        assert.equal(connectionID1, connID)
    })

    it("Alice Edge Agent accepts the invitation(second) from the router", async function () {
        let res = await didExchangeClient.acceptInvitation('wasm', aliceAgent, invitation2)
        let connID = await didExchangeClient.watchForConnection(aliceAgent, completedState)
        connectionID2 = res.connection_id
        assert.equal(connectionID2, connID)
    })

    it("Alice Edge Agent registers connections", async function () {
        await aliceAgent.mediator.register({"connectionID": connectionID1})
        await aliceAgent.mediator.register({"connectionID": connectionID2})
    })

    it("Alice Edge Agent validates router`s connections", async function () {
        let resp = await aliceAgent.mediator.getConnections()
        assert.notEqual(connectionID1, connectionID2)

        assert.isTrue(resp.connections.includes(connectionID1))
        assert.isTrue(resp.connections.includes(connectionID2))
    })
})

