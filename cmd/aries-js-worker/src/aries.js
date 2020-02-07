/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict'

const inNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null
const inBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';

// base path to load assets from at runtime
const __publicPath = _ => {
    if (inNode) {
        // TODO determine module_path at runtime
        return process.cwd() + "/node_modules/@hyperledger/aries-framework-go/"
    } else if (inBrowser) {
        return "/aries-framework-go/"
    } else {
        // TODO #1127 - throw error or use default?
    }
}

__webpack_public_path__ = __publicPath()

const { _getWorker } = require("worker_loader")

// TODO not all browsers support private members of classes
/* @class Aries provides Aries SSI-agent functions. */
export const Aries = new function() {
    // TODO synchronize access on this map?
    this._pending = new Map()

    /**
     * Test methods.
     * TODO - remove. Used for testing.
     * @type {{_echo: (function(*=): Promise<String>)}}
     * @private
     */
    this._test = {

        /**
         * Returns the input text prepended with "echo: ".
         * TODO - remove.
         * @param text
         * @returns {Promise<String>}
         * @private
         */
        _echo: async function(text) {
            return Aries._invoke("test", "echo", text, "timeout while accepting invitation")
        }
    }

    this.didexchange = {
        pkgname : "didexchange",
        CreateInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "CreateInvitation", text, "timeout while creating invitation")
        },
        ReceiveInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "ReceiveInvitation", text, "timeout while receiving invitation")
        },
        AcceptInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "AcceptInvitation", text, "timeout while accepting invitation")
        },
        AcceptExchangeRequest: async function(text) {
            return Aries._invoke(this.pkgname, "AcceptExchangeRequest", text, "timeout while accepting exchange request")
        },
        CreateImplicitInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "CreateImplicitInvitation", text, "timeout while creating implicit invitation")
        },
        RemoveConnection: async function(text) {
            return Aries._invoke(this.pkgname, "RemoveConnection", text, "timeout while removing invitation")
        },
        QueryConnectionByID: async function(text) {
            return Aries._invoke(this.pkgname, "QueryConnectionByID", text, "timeout while querying connection by ID")
        },
        QueryConnections: async function(text) {
            return Aries._invoke(this.pkgname, "QueryConnections", text, "timeout while querying connections")
        }
    }

    this.messaging = {
        pkgname : "messaging",
        RegisteredServices: async function(text) {
            return Aries._invoke(this.pkgname, "RegisteredServices", text, "timeout while getting list of registered services")
        },
        RegisterMessageService: async function(text) {
            return Aries._invoke(this.pkgname, "RegisterMessageService", text, "timeout while registering service")
        },
        RegisterHTTPMessageService: async function(text) {
            return Aries._invoke(this.pkgname, "RegisterHTTPMessageService", text, "timeout while registering HTTP service")
        },
        UnregisterMessageService: async function(text) {
            return Aries._invoke(this.pkgname, "UnregisterMessageService", text, "timeout while unregistering service")
        },
        SendNewMessage: async function(text) {
            return Aries._invoke(this.pkgname, "SendNewMessage", text, "timeout while sending new message")
        },
        SendReplyMessage: async function(text) {
            return Aries._invoke(this.pkgname, "SendReplyMessage", text, "timeout while sending reply message")
        }
    }

    this.vdri = {
        pkgname : "vdri",
        CreatePublicDID: async function(text) {
            return Aries._invoke(this.pkgname, "CreatePublicDID", text, "timeout while creating public DID")
        },
    }

    this.router = {
        pkgname : "router",
        Register: async function(text) {
            return Aries._invoke(this.pkgname, "Register", text, "timeout while registering router")
        },
    }

    this._newMsg = function(pkg, fn, payload) {
        return {
            // TODO there are several approaches to generate random strings:
            // - which should we implement? do we need cryptographic-grade randomness for this?
            // - alternatively, should the generator be provided by the client?
            id: Math.random().toString(36).slice(2),
            pkg: pkg,
            fn: fn,
            payload: payload
        }
    }

    this._invoke = async function(pkg, fn, arg, msgTimeout) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(_ => reject(new Error(msgTimeout)), 5000)
            const msg = Aries._newMsg(pkg, fn, arg)
            Aries._pending.set(msg.id, result => {
                clearTimeout(timer)
                if (result.isErr) {
                    reject(new Error(result.errMsg))
                }
                resolve(result.payload)
            })
            Aries._worker.postMessage(msg)
        })
    }

    this.getWorker = () => {
        return _getWorker(this._pending)
    }

    this._worker = this.getWorker()
}

