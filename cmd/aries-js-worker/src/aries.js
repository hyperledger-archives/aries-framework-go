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

// TODO synchronize access on this map?
const PENDING = new Map()
const WORKER = _getWorker(PENDING)

// TODO Aries should be a singleton

// TODO implement Aries options

// TODO not all browsers support private members of classes
/* @class Aries provides Aries SSI-agent functions. */
/**
 * Aries provides Aries SSI-agent functions.
 * @param opts initialization options.
 * @constructor
 */
export const Aries = function(opts) {
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
        createInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "CreateInvitation", text, "timeout while creating invitation")
        },
        receiveInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "ReceiveInvitation", text, "timeout while receiving invitation")
        },
        acceptInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "AcceptInvitation", text, "timeout while accepting invitation")
        },
        acceptExchangeRequest: async function(text) {
            return Aries._invoke(this.pkgname, "AcceptExchangeRequest", text, "timeout while accepting exchange request")
        },
        createImplicitInvitation: async function(text) {
            return Aries._invoke(this.pkgname, "CreateImplicitInvitation", text, "timeout while creating implicit invitation")
        },
        removeConnection: async function(text) {
            return Aries._invoke(this.pkgname, "RemoveConnection", text, "timeout while removing invitation")
        },
        queryConnectionByID: async function(text) {
            return Aries._invoke(this.pkgname, "QueryConnectionByID", text, "timeout while querying connection by ID")
        },
        queryConnections: async function(text) {
            return Aries._invoke(this.pkgname, "QueryConnections", text, "timeout while querying connections")
        }
    }

    this.messaging = {
        pkgname : "messaging",
        registeredServices: async function(text) {
            return Aries._invoke(this.pkgname, "RegisteredServices", text, "timeout while getting list of registered services")
        },
        registerMessageService: async function(text) {
            return Aries._invoke(this.pkgname, "RegisterMessageService", text, "timeout while registering service")
        },
        registerHTTPMessageService: async function(text) {
            return Aries._invoke(this.pkgname, "RegisterHTTPMessageService", text, "timeout while registering HTTP service")
        },
        unregisterMessageService: async function(text) {
            return Aries._invoke(this.pkgname, "UnregisterMessageService", text, "timeout while unregistering service")
        },
        sendNewMessage: async function(text) {
            return Aries._invoke(this.pkgname, "SendNewMessage", text, "timeout while sending new message")
        },
        sendReplyMessage: async function(text) {
            return Aries._invoke(this.pkgname, "SendReplyMessage", text, "timeout while sending reply message")
        }
    }

    this.vdri = {
        pkgname : "vdri",
        createPublicDID: async function(text) {
            return Aries._invoke(this.pkgname, "CreatePublicDID", text, "timeout while creating public DID")
        },
    }

    this.router = {
        pkgname : "router",
        register: async function(text) {
            return Aries._invoke(this.pkgname, "Register", text, "timeout while registering router")
        },
        unregister: async function(text) {
            return Aries._invoke(this.pkgname, "Unregister", text, "timeout while registering router")
        }
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
            PENDING.set(msg.id, result => {
                clearTimeout(timer)
                if (result.isErr) {
                    reject(new Error(result.errMsg))
                }
                resolve(result.payload)
            })
            WORKER.postMessage(msg)
        })
    }
}

