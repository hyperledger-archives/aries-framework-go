/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// This is a test nodejs app for developers to test WASM integration.

const { Framework } = require('./dist/node/aries.js');

(async () => {
    const aries = await new Framework({
        assetsPath: process.cwd() + "/dist/assets",
        "agent-default-label": "dem-js-agent",
        "http-resolver-url": [],
        "auto-accept": true,
        "outbound-transport": ["ws", "http"],
        "transport-return-route": "all",
        "log-level": "debug"
    })

    // sample invitation
    const invitation = {
        "@id":"4d26ad47-c71b-4e2e-9358-0a76f7fa77e4",
        "@type":"https://didcomm.org/didexchange/1.0/invitation",
        "label":"demo-js-agent",
        "recipientKeys":["7rADm5sA9FHB4enuYXj6PJZDAm1JcesKmbtx7Qh8YZrg"],
        "serviceEndpoint":"routing:endpoint"
    };

    // listen for connection 'received' notification
    aries.startNotifier(notice => {
        const connection = notice.payload
        // accept invitation
        aries.didexchange.acceptInvitation(connection.connection_id)
    }, ["connections"])
    // receive invitation
    aries.didexchange.receiveInvitation(invitation)

    // listen for connection 'completed' notification
    aries.startNotifier(notice => {
        const connection = notice.payload
        if (connection.state === "completed") {
            console.log("connection completed!")
        }
    }, ["connections"])

    // release resources
    aries.destroy()
})()
