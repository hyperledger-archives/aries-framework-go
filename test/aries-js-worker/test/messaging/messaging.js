/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

import {newDIDExchangeClient} from "../didexchange/didexchange_e2e.js";
import {newAries} from "../common";

const basicMsgType = "https://didcomm.org/basicmessage/1.0/message"
const basicMsgSvcName = "basic-msg-svc-demo"
const sampleMsg = {
    "@id": "1d9a1589-9d7b-4308-9fab-8ee9730720c2",
    "@type": basicMsgType,
    "~l10n": {"locale": "en"},
    "sent_time": "2020-03-05T16:59:47.489789-05:00",
    "content": "Your hovercraft is full of eels."
}

const sampleReplyMsg = {
    "@id": "1d9a1589-9d7b-4308-9fab-8ee9730720c2",
    "@type": basicMsgType,
    "~l10n": {"locale": "en"},
    "sent_time": "2020-03-05T16:59:47.489789-05:00",
    "content": "Hold my beer, I got this."
}

// scenarios
describe("Basic Messaging", function () {
    const receiver_agent_name = "msg-receiver"
    const sender_agent_name = "msg-sender"

    let destinationConnID
    let didexClient
    let sender, receiver
    let lastReceivedMsgID

    before(async () => {
        didexClient = await newDIDExchangeClient(sender_agent_name, receiver_agent_name)
        assert.isNotNull(didexClient)

        const connections = await didexClient.performDIDExchangeE2E()
        assert.isNotEmpty(connections)

        destinationConnID = connections[0]
        sender = didexClient.agent1
        receiver = didexClient.agent2
    })

    after(async () => {
        await didexClient.destroy()
    })

    it("receiver registers basic message service", function (done) {
        receiver.messaging.registerService({
            "name": `${basicMsgSvcName}`,
            "type": `${basicMsgType}`,
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it("receiver gets list of registered message services", function (done) {
        receiver.messaging.services().then(
            resp => {
                try {
                    assert.lengthOf(resp.names, 1, `1 message service is registered`)
                } catch (err) {
                    done(err)
                }
                done()
            },
            err => done(err)
        )
    })

    it("sender sends basic message to receiver", async function () {
        sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})

        const incomingMsg = await new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error("time out waiting for incoming message")), 5000)
            const stop = receiver.startNotifier(msg => {
                stop()
                lastReceivedMsgID = msg.payload.message["@id"]
                resolve(msg.payload.message)
            }, [basicMsgSvcName])
        })

        assert.equal(incomingMsg["@id"], sampleMsg["@id"])
        assert.equal(incomingMsg["@type"], sampleMsg["@type"])
        assert.equal(incomingMsg.content, sampleMsg.content)
    })

    it("sender registers basic message service", function (done) {
        sender.messaging.registerService({
            "name": `${basicMsgSvcName}`,
            "type": `${basicMsgType}`,
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it("receiver replies to last received basic message", async function () {
        receiver.messaging.reply({"message_ID": `${lastReceivedMsgID}`, "message_body": sampleReplyMsg})

        const incomingMsg = await new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error("time out waiting for incoming message")), 5000)
            const stop = sender.startNotifier(msg => {
                stop()
                resolve(msg.payload.message)
            }, [basicMsgSvcName])
        })

        assert.equal(incomingMsg["@id"], sampleReplyMsg["@id"])
        assert.equal(incomingMsg["@type"], sampleReplyMsg["@type"])
        assert.equal(incomingMsg.content, sampleReplyMsg.content)
    })

    it("receiver loses connection from router", async function () {
        await receiver.destroy()
    })

    it("sender sends several messages to receiver who is offline", async function () {
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
        await sender.messaging.send({"connection_ID": `${destinationConnID}`, "message_body": sampleMsg})
    })

    it("receiver reconnects with router and checks pending message status", async function () {
        receiver = await newAries(receiver_agent_name, receiver_agent_name)

        await receiver.messaging.registerService({
            "name": `${basicMsgSvcName}`,
            "type": `${basicMsgType}`,
        })

        let status = await receiver.mediator.status({connectionID: didexClient.agent2RouterConnection})
        assert.equal(status.message_count, 7)

        receiver.mediator.batchPickup({
            connectionID: didexClient.agent2RouterConnection,
            batch_size: status.message_count
        })


        let msgCount = 0
        const incomingMsg = await new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error("time out waiting for incoming message")), 15000)
            const stop = receiver.startNotifier(msg => {
                msgCount++
                if (msgCount < status.message_count) {
                    return
                }
                stop()
                lastReceivedMsgID = msg.payload.message["@id"]
                resolve(msg.payload.message)
            }, [basicMsgSvcName])
        })

        assert.equal(msgCount, status.message_count)
        assert.equal(incomingMsg["@id"], sampleMsg["@id"])
        assert.equal(incomingMsg["@type"], sampleMsg["@type"])
        assert.equal(incomingMsg.content, sampleMsg.content)
    })

    it("sender unregisters basic message service", function (done) {
        sender.messaging.unregisterService({
            "name": `${basicMsgSvcName}`
        }).then(
            resp => {
                done()
            },
            err => done(err)
        )
    })

    it("sender gets updated list of registered message services", function (done) {
        sender.messaging.services().then(
            resp => {
                try {
                    assert.lengthOf(resp.names, 0, `0 message service is registered`)
                } catch (err) {
                    done(err)
                }
                done()
            },
            err => done(err)
        )
    })

})
