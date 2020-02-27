/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

self.importScripts("./agent-rest-client.js")

postMessage({topic: "asset-ready"})

// TODO synchronized access to controller
let handler, controller, notifier

const wsNormalClosureCode = 1000

const ariesHandle = {
    aries: {
        Start: (data) => {
            if (controller) {
                return newResponse(data.id, null, "aries already started");
            }

            if (!data.payload["agent-rest-url"]) {
                return newResponse(data.id, null, "'agent-rest-url' is required");
            }

            if (data.payload["agent-rest-wshook"]){
                notifier = new wsnotifier(data.payload["agent-rest-wshook"], (msg) => {
                    postMessage(msg)
                });
            }


            controller = new RESTAgent.Client(data.payload["agent-rest-url"], data.payload["agent-rest-token"]);
            return newResponse(data.id, "aries is started");
        },
        Stop: (data) => {
            if (!controller) {
                return newResponse(data.id, null, "aries already stopped");
            }
            controller = null;
            return newResponse(data.id, "aries stopped");
        }
    }
}

onmessage = async function (e) {
    console.debug('message received :', e.data);
    if (ariesHandle[e.data.pkg] && ariesHandle[e.data.pkg][e.data.fn]) {
        postMessage(ariesHandle[e.data.pkg][e.data.fn](e.data));
        return;
    }

    if (controller) {
        try{
            const response = await controller.handle(e.data);
            postMessage(newResponse(e.data.id, response));
            console.debug("response from rest controller", response);
        } catch(error){
            console.debug("error from rest controller", error.response);
            postMessage(newResponse(e.data.id, null, JSON.stringify(error.response.data)));
        }
        return;
    }

    postMessage(newResponse(e.data.id, null, "aries not started"));
}


function newResponse(id, payload, errMsg, topic) {
    const isErr = (errMsg) ? true : false;
    return {
        id: id,
        payload: payload,
        isErr: isErr,
        errMsg: errMsg,
        topic: topic
    };
}

const wsnotifier = class {
    constructor(url, postMsg) {
        this.socket = new WebSocket(url);
        this.socket.addEventListener('message', function (event) {
            const incoming = JSON.parse(event.data)
            postMsg(newResponse(incoming.id,  incoming.message, "", incoming.topic));
        });
    }
    stop(){
        this.socket.close(wsNormalClosureCode, "stopped notifier in aries-js-worker")
    }
};