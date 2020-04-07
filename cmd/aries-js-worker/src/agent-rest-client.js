/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/


import axios from 'axios';

// All REST endpoints provided by agent controller
const pkgs = {
    didexchange: {
        CreateInvitation: {
            path: "/connections/create-invitation",
            method: "POST"
        },
        ReceiveInvitation: {
            path: "/connections/receive-invitation",
            method: "POST"
        },
        AcceptInvitation: {
            path: "/connections/{id}/accept-invitation",
            method: "POST",
            pathParam:"id"
        },
        AcceptExchangeRequest: {
            path: "/connections/{id}/accept-request",
            method: "POST",
            pathParam:"id"
        },
        CreateImplicitInvitation: {
            path: "/connections/create-implicit-invitation",
            method: "POST"
        },
        RemoveConnection: {
            path: "/connections/{id}/remove",
            method: "POST",
            pathParam:"id"
        },
        QueryConnectionByID: {
            path: "/connections/{id}",
            method: "GET",
            pathParam:"id"
        },
        QueryConnections: {
            path: "/connections",
            method: "GET"
        },
    },
    vdri: {
        CreatePublicDID: {
            path: "/vdri/create-public-did?method={method}&header={header}",
            method: "POST",
            pathParam:"id",
            queryStrings: ["method","header"]
        },
        SaveDID: {
            path: "/vdri/did",
            method: "POST"
        },
        GetDID: {
            path: "/vdri/did/{id}",
            method: "GET",
            pathParam:"id"
        },
        GetDIDs: {
            path: "/vdri/did/records",
            method: "GET",
        },
    },
    messaging: {
        RegisteredServices: {
            path: "/message/services",
            method: "GET"
        },
        RegisterMessageService: {
            path: "/message/register-service",
            method: "POST"
        },
        RegisterHTTPMessageService: {
            path: "/http-over-didcomm/register",
            method: "POST"
        },
        UnregisterMessageService: {
            path: "/message/unregister-service",
            method: "POST"
        },
        SendNewMessage: {
            path: "/message/send",
            method: "POST"
        },
        SendReplyMessage: {
            path: "/message/reply",
            method: "POST"
        },
    },
    route: {
        Register: {
            path: "/route/register",
            method: "POST"
        },
        Unregister: {
            path: "/route/unregister",
            method: "DELETE"
        },
        GetConnection: {
            path: "/route/connection",
            method: "GET"
        },
    },
    verifiable: {
        ValidateCredential: {
            path: "/verifiable/credential/validate",
            method: "POST"
        },
        SaveCredential: {
            path: "/verifiable/credential",
            method: "POST"
        },
        GetCredential: {
            path: "/verifiable/credential/{id}",
            method: "GET",
            pathParam:"id"
        },
        GetCredentialByName: {
            path: "/verifiable/credential/name/{name}",
            method: "GET",
            pathParam:"name"
        },
        GetCredentials: {
            path: "/verifiable/credentials",
            method: "GET",
        },
        GeneratePresentation: {
            path: "/verifiable/presentation/generate",
            method: "POST"
        },
        GeneratePresentationByID: {
            path: "/verifiable/credential/{id}/presentation",
            method: "GET",
            pathParam:"id"
        },
    },
    kms: {
        CreateKeySet: {
            path: "/kms/keyset",
            method: "POST",
        },
    },
}

/**
 * Agent rest client for given agent endpoint
 * @param url is rest endpoint url
 * @class
 */
export const Client = class {
    constructor(url, token) {
        this.url = url
        this.token = token
    }

    async handle(request) {
        const r = (pkgs[request.pkg]) ? pkgs[request.pkg][request.fn] : null;
        if (!r) {
            return "unable to find given pkg/fn:"+request.pkg+"/"+request.fn;
        }

        let url =  this.url + r.path
        if (r.pathParam){
            const p = ((request.payload[r.pathParam])) ? (request.payload[r.pathParam]) : "";
            url = this.url + r.path.replace("{"+r.pathParam+"}", p);
        }

        if (r.queryStrings){
            r.queryStrings.forEach(p => {
                url = url.replace("{"+ p +"}", (request.payload[p]) ? request.payload[p] : "");
            })
        }

        console.debug(`[${r.method}] ${url}, request ${JSON.stringify(request.payload)}`)

        let headers = {}
        if (this.token) {
            headers = {
                "Authorization": `Bearer ${this.token}`
            }
        }

        const resp = await axios({
                method: r.method,
                url: url,
                headers: headers,
                data: request.payload
            });

        return resp.data;
    }
};


