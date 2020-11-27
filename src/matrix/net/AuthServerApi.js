import {ObservableValue} from "../../observable/ObservableValue.js";
import {ConnectionError} from "../error.js";

export class AuthServerApi {
    constructor({ authServer, request, createTimeout, crypto, session }) {
        this._authserver = authServer;
        this._requestFn = request;
        this._createTimeout = createTimeout;
        this._crypto = crypto;
        this._accessToken = new ObservableValue();

        if (session) {
            this.restore(session);
        }
    }

    async discover() {
        const { status, body } = await this._requestFn(`${this._authserver}/.well-known/openid-configuration`, {
            method: "GET",
            format: "json",
        }).response();

        if (status >= 400) {
            throw new ConnectionError(`HTTP error status ${status}`);
        }

        this._configuration = body;
        return this._configuration;
    }

    async _getConfiguration() {
        if (!this._configuration) {
            await this.discover();
        }
        return this._configuration;
    }

    accessToken() {
        return this._accessToken;
    }

    async registerClient() {
        const endpoint = (await this._getConfiguration())["registration_endpoint"];
        const metadata = this._clientMetadata();

        const reqBody = JSON.stringify(metadata);

        const { status, body } = await this._requestFn(endpoint, {
            method: "POST",
            format: "json",
            headers: new Map([
                ["Accept", "application/json"],
                ["Content-Type", "application/json"],
                ["Content-Length", reqBody.length],
            ]),
            body: reqBody,
        }).response();

        if (status >= 400) {
            throw new ConnectionError(`HTTP error status ${status}`);
        }

        this._registration = body;
        this._clientId = body["client_id"];
        return this._registration;
    }

    async _getClientId() {
        if (!this._clientId) {
            await this.registerClient();
        }
        return this._clientId;
    }

    async _deriveChallenge(verifier) {
        const encoder = new TextEncoder();
        const view = encoder.encode(verifier);
        const digest = await this._crypto.digest("SHA-256", view);

        const b64 = this._crypto.base64ArrayBuffer(digest);
        return b64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    async startAuthorization({ hint }) {
        const endpoint = new URL((await this._getConfiguration())["authorization_endpoint"]);
        const state = this._crypto.randomString(10);
        const nonce = this._crypto.randomString(10);
        const verifier = this._crypto.randomString(64);
        const challenge = await this._deriveChallenge(verifier);

        const params = {
            client_id: await this._getClientId(),
            state,
            nonce,
            redirect_uri: this._redirectUri(),
            scope: "openid",
            response_type: "code",
            response_mode: "fragment",
            code_challenge: challenge,
            code_challenge_method: "S256",
            login_hint: hint,
        };

        for (const [key, value] of Object.entries(params))
            if (value)
                endpoint.searchParams.set(key, value);

        return [endpoint.toString(), { state, nonce, verifier }];
    }

    async completeAuthorization(session, params) {
        if (params.error) {
            if (params.error_description) {
                throw new Error(params.error_description);
            } else {
                throw new Error(params.error);
            }
        }

        if (!params.code) {
            throw new Error("no code found");
        }

        if (params.state !== session.state) {
            throw new Error("state mismatch");
        }

        const endpoint = (await this._getConfiguration())["token_endpoint"];

        const reqBody = new URLSearchParams({
            "grant_type": "authorization_code",
            "code_verifier": session.verifier,
            "client_id": await this._getClientId(),
            "code": params.code,
            "redirect_uri": this._redirectUri(),
        }).toString();

        const { status, body } = await this._requestFn(endpoint, {
            method: "POST",
            format: "json",
            headers: new Map([
                ["Accept", "application/json"],
                ["Content-Type", "application/x-www-form-urlencoded"],
                ["Content-Length", reqBody.length],
            ]),
            body: reqBody,
        }).response();

        if (status >= 400) {
            if (body.error)
            throw new ConnectionError(`HTTP error status ${status}`);
        }

        this._token = body;
        this._accessToken.set(body.access_token);
        return this._accessToken;
    }

    save() {
        return {
            registration: this._registration,
            configuration: this._configuration,
            token: this._token,
        };
    }

    restore(saved) {
        this._configuration = saved.configuration;
        this._registration = saved.registration;
        this._token = saved.token;
        this._accessToken.set(this._token.access_token);
        this._authserver = this._configuration.issuer;
        this._clientId = this._registration.client_id;
    }

    _redirectUri() {
        // TODO: this should be dynamic
        return "http://localhost:3000/assets/oauth2-callback.html";
    }

    _clientMetadata() {
        // TODO: this should be dynamic
        // TODO: give a signed software-statement
        return {
            "application_type": "web",
            "client_name": "Hydrogen Web",
            "client_uri": "http://localhost:3000/",
            "logo_uri": "https://raw.githubusercontent.com/vector-im/hydrogen-web/master/assets/icon.svg",
            "tos_uri": "https://element.io/terms-of-services",
            "policy_uri": "https://element.io/privacy",
            "redirect_uris": [
                this._redirectUri(),
            ],
            "response_types": ["code"],
            "grant_types": [
                "authorization_code",
                "refresh_token"
            ]
        }
    }
}
