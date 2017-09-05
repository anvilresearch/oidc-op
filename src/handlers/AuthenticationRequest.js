'use strict'

/**
 * Dependencies
 * @ignore
 */
const BaseRequest = require('./BaseRequest')
const AccessToken = require('../AccessToken')
const AuthorizationCode = require('../AuthorizationCode')
const IDToken = require('../IDToken')
const { JWT, JWK, JWKSet } = require('@trust/jose')
const { URL } = require('whatwg-url')

/**
 * AuthenticationRequest
 */
class AuthenticationRequest extends BaseRequest {

  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    let {host} = provider
    let request = new AuthenticationRequest(req, res, provider)

    return Promise
      .resolve(request)
      .then(request.loadClient)
      .then(request.decodeRequestParam)
      .then(request.validate)
      .then(host.authenticate)
      .then(host.obtainConsent)
      .then(request.authorize)
      .catch(err => request.error(err))
  }

  /**
   * Constructor
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  constructor (req, res, provider) {
    super(req, res, provider)
    this.params = AuthenticationRequest.getParams(this)
    this.responseTypes = AuthenticationRequest.getResponseTypes(this)
    this.responseMode = AuthenticationRequest.getResponseMode(this)
  }

  /**
   * loadClient
   *
   * @description
   * Loads the client registration from the backend store
   *
   * @param request {AuthenticationRequest}
   *
   * @returns {Promise<AuthenticationRequest>}
   */
  loadClient (request) {
    let { provider, params } = request

    if (!params.client_id) {
      // An error for the missing client_id will be thrown in validate()
      return Promise.resolve(request)
    }

    return provider.backend.get('clients', params.client_id)

      .then(client => {  // client registration
        request.client = client

        if (client && client.jwks) {
          // pre-registered client keys (for signing request objects, etc)
          return JWKSet.importKeys(client.jwks)
            .then(importedJwks => {
              client.jwks = importedJwks
            })
        }
      })

      .then(() => request)
  }

  /**
   * decodeRequestParam
   *
   * @description
   * Decodes, validates and loads a Request Object (passed by value)
   *
   * @see https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
   *
   * @param request {AuthenticationRequest}
   *
   * @returns {Promise<AuthenticationRequest>}
   */
  decodeRequestParam (request) {
    let { params } = request

    if (!params['request']) {
      return Promise.resolve(request)  // Pass through, no request param present
    }

    let requestJwt

    return Promise.resolve()
      .then(() => JWT.decode(params['request']))

      .catch(err => {
        request.redirect({
          error: 'invalid_request_object',
          error_description: err.message
        })
      })

      .then(jwt => { requestJwt = jwt })

      .then(() => {
        if (requestJwt.payload.key) {
          return request.loadCnfKey(requestJwt.payload.key)
            .catch(err => {
              request.redirect({
                error: 'invalid_request_object',
                error_description: 'Error importing cnf key: ' + err.message
              })
            })
        }
      })

      .then(() => request.validateRequestParam(requestJwt))

      .then(requestJwt => {
        request.params = Object.assign({}, params, requestJwt.payload)
      })

      .then(() => request)
  }

  /**
   * loadCnfKey
   *
   * @description
   * Loads the Proof of Possession confirmation key (from the `request` param)
   *
   * @see https://tools.ietf.org/html/rfc7800#section-3.1
   * @see https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution-03#section-5
   *
   * @param jwk {JWK}
   *
   * @returns {Promise<JWK>} Imported key
   */
  loadCnfKey (jwk) {
    // jwk.use = jwk.use || 'sig'  // make sure key usage is not omitted

    // Importing the key serves as additional validation
    return JWK.importKey(jwk)
      .then(importedJwk => {
        this.cnfKey = importedJwk  // has a cryptoKey property

        return importedJwk
      })
  }

  /**
   * validateRequestParam
   *
   * @description
   * Validates the Request Object jwt (passed by value)
   *
   * @param requestJwt {JWT} Decoded request object
   *
   * @returns {Promise<JWT>} Resolves with the decoded request jwt
   */
  validateRequestParam (requestJwt) {
    let { params } = this
    let { payload } = requestJwt

    return Promise.resolve()

      .then(() => {
        // request and request_uri parameters MUST NOT be included in Request Objects
        if (payload.request) {
          return this.redirect({
            error: 'invalid_request_object',
            error_description: 'Illegal request claim in payload'
          })
        }
        if (payload.request_uri) {
          return this.redirect({
            error: 'invalid_request_object',
            error_description: 'Illegal request_uri claim in payload'
          })
        }
      })

      .then(() => {
        // So that the request is a valid OAuth 2.0 Authorization Request, values
        // for the response_type and client_id parameters MUST be included using
        // the OAuth 2.0 request syntax, since they are REQUIRED by OAuth 2.0.
        // The values for these parameters MUST match those in the Request Object,
        // if present.
        if (payload.client_id && payload.client_id !== params.client_id) {
          return this.forbidden({
            error: 'unauthorized_client',
            error_description: 'Mismatching client id in request object'
          })
        }

        if (payload.response_type && payload.response_type !== params.response_type) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Mismatching response type in request object',
          })
        }

        // Even if a scope parameter is present in the Request Object value, a scope
        // parameter MUST always be passed using the OAuth 2.0 request syntax
        // containing the openid scope value to indicate to the underlying OAuth 2.0
        // logic that this is an OpenID Connect request.
        if (payload.scope && payload.scope !== params.scope) {
          return this.redirect({
            error: 'invalid_scope',
            error_description: 'Mismatching scope in request object',
          })
        }

        // TODO: What to do with this? SHOULD considered harmful, indeed...
        // If signed, the Request Object SHOULD contain the Claims iss
        // (issuer) and aud (audience) as members. The iss value SHOULD be the
        // Client ID of the RP, unless it was signed by a different party than the
        // RP. The aud value SHOULD be or include the OP's Issuer Identifier URL.
      })

      .then(() => this.validateRequestParamSignature(requestJwt))

      .then(() => requestJwt)
  }

  /**
   * validateRequestParamSignature
   *
   * @param requestJwt {JWT} Decoded request object
   *
   * @returns {Promise}
   */
  validateRequestParamSignature (requestJwt) {
    // From https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata

    // request_object_signing_alg
    //   OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing
    //   Request Objects sent to the OP. All Request Objects from this Client
    //   MUST be rejected, if not signed with this algorithm. Request Objects
    //   are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core].
    //   This algorithm MUST be used both when the Request Object is passed by
    //   value (using the request parameter) and when it is passed by reference
    //   (using the request_uri parameter). Servers SHOULD support RS256.
    //   The value none MAY be used. The default, if omitted, is that any
    //   algorithm supported by the OP and the RP MAY be used.

    // From https://openid.net/specs/openid-connect-core-1_0.html#SignedRequestObject

    // The Request Object MAY be signed or unsigned (plaintext). When it is
    // plaintext, this is indicated by use of the none algorithm [JWA] in the
    // JOSE Header.

    // For Signature Validation, the alg Header Parameter in the JOSE Header
    // MUST match the value of the request_object_signing_alg set during Client
    // Registration or a value that was pre-registered by
    // other means. The signature MUST be validated against the appropriate key
    // for that client_id and algorithm.

    if (!this.client) {
      // No client_id, or no registration found for it
      // An error will be thrown downstream in `validate()`
      return Promise.resolve()
    }

    let clientJwks = this.client.jwks
    let registeredSigningAlg = this.client['request_object_signing_alg']

    let signedRequest = requestJwt.header.alg !== 'none'
    let signatureRequired = clientJwks ||
      (registeredSigningAlg && registeredSigningAlg !== 'none')

    if (!signedRequest && !signatureRequired) {
      // Unsigned, signature not required - ok
      return Promise.resolve()
    }

    return Promise.resolve()
      .then(() => {
        if (signedRequest && !clientJwks) {
          // No keys pre-registered, but the request is signed. Throw error
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Signed request object, but no jwks pre-registered',
          })
        }

        if (signedRequest && registeredSigningAlg === 'none') {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Signed request object, but no signature allowed by request_object_signing_alg',
          })
        }

        if (!signedRequest && signatureRequired) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Signature required for request object',
          })
        }

        if (registeredSigningAlg && requestJwt.header.alg !== registeredSigningAlg) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Request signed by algorithm that does not match registered request_object_signing_alg value',
          })
        }

        // Request is signed. Validate signature against registered jwks
        let keyMatch = requestJwt.resolveKeys(clientJwks)

        if (!keyMatch) {
          return this.redirect({
            error: 'invalid_request',
            error_description: 'Cannot resolve signing key for request object',
          })
        }

        return requestJwt.verify()
          .then(verified => {
            if (!verified) {
              return this.redirect({
                error: 'invalid_request',
                error_description: 'Invalid request object signature',
              })
            }
          })
      })
  }

  /**
   * Validate Request
   *
   * @param {AuthenticationRequest} request
   *
   * @returns {AuthenticationRequest}
   */
  validate (request) {
    const { params, client } = request

    // CLIENT ID IS REQUIRED
    if (!params.client_id) {
      return request.forbidden({
        error: 'unauthorized_client',
        error_description: 'Missing client id'
      })
    }

    // REDIRECT URI IS REQUIRED
    if (!params.redirect_uri) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect uri',
      })
    }

    // UNKNOWN CLIENT
    if (!client) {
      return request.unauthorized({
        error: 'unauthorized_client',
        error_description: 'Unknown client'
      })
    }

    // REDIRECT_URI MUST MATCH
    if (!AuthenticationRequest.validateRedirectUri(client.redirect_uris, params.redirect_uri)) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Mismatching redirect uri'
      })
    }

    // RESPONSE TYPE IS REQUIRED
    if (!params.response_type) {
      return request.redirect({
        error: 'invalid_request',
        error_description: 'Missing response type',
      })
    }

    // SCOPE IS REQUIRED
    if (!params.scope) {
      return request.redirect({
        error: 'invalid_scope',
        error_description: 'Missing scope',
      })
    }

    // OPENID SCOPE IS REQUIRED
    if (!params.scope.includes('openid')) {
      return request.redirect({
        error: 'invalid_scope',
        error_description: 'Missing openid scope'
      })
    }

    // NONCE MAY BE REQUIRED
    if (!request.requiredNonceProvided()) {
      return request.redirect({
        error: 'invalid_request',
        error_description: 'Missing nonce'
      })
    }

    // RESPONSE TYPE MUST BE SUPPORTED
    // TODO is this something the client can configure too?
    if (!request.supportedResponseType()) {
      return request.redirect({
        error: 'unsupported_response_type',
        error_description: 'Unsupported response type'
      })
    }

    // RESPONSE MODE MUST BE SUPPORTED
    // TODO is this something the client can configure too?
    if (!request.supportedResponseMode()) {
      return request.redirect({
        error: 'unsupported_response_mode',
        error_description: 'Unsupported response mode'
      })
    }

    // VALID REQUEST
    return request
  }

  static validateRedirectUri (registeredUris, redirectUri) {
    // Drop hash fragment when validating against pre-registered uris
    let uriNoHash = (uri) => {
      uri = new URL(uri)
      uri.hash = ''
      return uri.toString()
    }

    return registeredUris.some(uri => uriNoHash(uri) === uriNoHash(redirectUri))
  }

  /**
   * Supported Response Type
   *
   * @returns {bool}
   */
  supportedResponseType () {
    let {params, provider} = this
    let supportedResponseTypes = provider.response_types_supported
    let requestedResponseType = params.response_type

    // TODO
    // verify that the requested response types are permitted
    // by client registration
    //
    // let registeredResponseTypes = client.response_types
    return supportedResponseTypes.includes(requestedResponseType)
  }

  /**
   * Supported Response Mode
   *
   * @returns {bool}
   */
  supportedResponseMode () {
    let {params, provider} = this
    let supportedResponseModes = provider.response_modes_supported
    let requestedResponseMode = params.response_mode

    if (!requestedResponseMode) {
      return true
    } else {
      return supportedResponseModes.indexOf(requestedResponseMode) !== -1
    }
  }

  /**
   * Required Nonce Provided
   *
   * @returns {bool}
   */
  requiredNonceProvided () {
    let {params} = this
    let {nonce, response_type: responseType} = params
    let requiring = ['id_token', 'token']

    if (!nonce && requiring.some(type => responseType.indexOf(type) !== -1)) {
      return false
    } else {
      return true
    }
  }

  /**
   * Authorize
   *
   * @param {AuthenticationRequest} request
   * @returns {Promise}
   */
  authorize (request) {
    if (request.consent === true) {
      return request.allow(request)
    } else {
      return request.deny(request)
    }
  }

  /**
   * Allow
   *
   * Given a completely validated request with an authenticated user and
   * consent, build a response incorporating auth code, tokens, and session
   * state.
   */
  allow (request) {
    return Promise.resolve({}) // initialize empty response
      .then(response => request.includeAccessToken(response))
      .then(response => request.includeAuthorizationCode(response))
      .then(response => request.includeIDToken(response))
      //.then(this.includeSessionState.bind(this))
      .then(response => request.redirect(response))
      // do some error handling here
  }

  /**
   * Deny
   *
   * Handle user's rejection of the client.
   */
  deny (request) {
    this.redirect({
      error: 'access_denied'
    })
  }

  /**
   * Include Access Token
   *
   * @returns {Promise}
   */
  includeAccessToken (response) {
    let {responseTypes} = this

    if (responseTypes.includes('token')) {
      return AccessToken.issueForRequest(this, response)
    }

    return Promise.resolve(response)
  }

  /**
   * Include Authorization Code
   *
   * @returns {Promise}
   */
  includeAuthorizationCode (response) {
    let {responseTypes, params, scope} = this
    let {provider, client, subject} = this
    let {backend} = provider

    if (responseTypes.includes('code')) {
      let code = this.random(16)
      let sub = subject['_id']
      let aud = client['client_id']
      let iat = Math.floor(Date.now() / 1000)
      let exp = iat + 600
      let max = params['max_age'] || client['default_max_age']
      let nonce = params['nonce']
      let redirect_uri = params['redirect_uri']

      let ac = new AuthorizationCode({
        code, sub, aud, exp, max, scope, nonce, redirect_uri
      })

      return backend.put('codes', code, ac)
        .then(() => {
          response['code'] = code
          return response
        })
    }

    return Promise.resolve(response)
  }

  /**
   * Include ID Token
   *
   * @returns {Promise}
   */
  includeIDToken (response) {
    let {responseTypes} = this

    if (responseTypes.includes('id_token')) {
      return IDToken.issueForRequest(this, response)
    }

    return Promise.resolve(response)
  }

  /**
   * Include Session State
   */
  includeSessionState (response) {
    // ...
  }
}

/**
 * Export
 */
module.exports = AuthenticationRequest

