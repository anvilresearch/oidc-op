'use strict'

/**
 * Dependencies
 * @ignore
 */
const crypto = require('webcrypto')
const BaseRequest = require('./BaseRequest')
const AccessToken = require('../AccessToken')
const AuthorizationCode = require('../AuthorizationCode')
const IDToken = require('../IDToken')

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

    Promise
      .resolve(request)
      .then(request.validate)
      .then(host.authenticate)  // QUESTION, what's the cleanest way to
      .then(host.obtainConsent) // bind this here?
      .then(request.authorize)
      .catch(request.internalServerError)
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
   * Validate Request
   *
   * @param {AuthenticationRequest} request
   * @returns {Promise}
   */
  validate (request) {
    let { params, provider } = request

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

    // RETURN A PROMISE WHICH WILL BE RESOLVED
    // IF THE REQUEST IS VALID. ALL ERROR CONDITIONS
    // SHOULD BE HANDLED HERE (WITH AN ERROR RESPONSE),
    // SO THERE'S NOTHING TO CATCH.
    return new Promise((resolve, reject) => {
      provider.backend.get('clients', params.client_id).then(client => {

        // UNKNOWN CLIENT
        if (!client) {
          return request.unauthorized({
            error: 'unauthorized_client',
            error_description: 'Unknown client'
          })
        }

        // ADD CLIENT TO REQUEST
        request.client = client

        // REDIRECT_URI MUST MATCH
        if (!client.redirect_uris.includes(params.redirect_uri)) {
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
        resolve(request)
      })
    })
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
      request.allow(request)
    } else {
      request.deny(request)
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
    Promise.resolve({}) // initialize empty response
      .then(this.includeAccessToken.bind(this))
      .then(this.includeAuthorizationCode.bind(this))
      .then(this.includeIDToken.bind(this))
      //.then(this.includeSessionState.bind(this))
      .then(this.redirect.bind(this))
      // do some error handling here
  }

  /**
   * Deny
   *
   * Handle user's rejection of the client.
   */
  deny (request) {
    let {params} = request
    let {state} = params

    this.redirect({
      error: 'access_denied', state
    })
  }

  /**
   * Include Access Token
   */
  includeAccessToken (response) {
    let {responseTypes, params, provider, client, subject, scope} = this

    if (responseTypes.includes('token')) {
      let alg = client['access_token_signed_response_alg'] || 'RS256'
      let key = provider.keys.token.signing[alg].privateKey
      let kid = provider.keys.token.signing[alg].publicJwk.kid
      let iss = provider.issuer
      let aud = client['client_id']
      let sub = subject['_id']
      let jti = this.random()
      let iat = Math.floor(Date.now() / 1000)
      let max = parseInt(params['max_age']) || client['default_max_age'] || 3600
      let exp = iat + max
      let header = {alg, kid}
      let payload = {iss, aud, sub, exp, iat, jti, scope}
      let jwt = new AccessToken({header, payload, key})

      // encode the JWT
      return jwt.encode()

        // set the response properties
        .then(compact => {
          response['access_token'] = compact
          response['token_type'] = 'Bearer'
          response['expires_in'] = max

          if (responseTypes.includes('code')) {
            response['refresh_token'] = this.random()
          }
        })

        // store access token
        .then(() => {
          let {header, payload} = jwt
          let {signature} = jwt

          return provider.backend.put('tokens', `${jti}`, {
            header, payload, signature
          })
        })

        // store optional refresh token
        .then(() => {
          let {header, payload} = jwt
          let {signature} = jwt
          let refresh = response['refresh_token']

          if (refresh) {
            return provider.backend.put('refresh', `${refresh}`, {
              header, payload, signature
            })
          }
        })

        // resolve the response
        .then(() => response)
    }

    return response
  }

  /**
   * Include Authorization Code
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

    return response
  }

  /**
   * Include ID Token
   */
  includeIDToken (response) {
    let {responseTypes, params, provider, client, subject} = this

    if (responseTypes.includes('id_token')) {
      let alg = client['id_token_signed_response_alg'] || 'RS256'
      let key = provider.keys['id_token'].signing[alg].privateKey
      let kid = provider.keys['id_token'].signing[alg].publicJwk.kid
      let iss = provider.issuer
      let aud = client['client_id']
      let sub = subject['_id']
      let iat = Math.floor(Date.now() / 1000)
      let max = parseInt(params['max_age']) || client['default_max_age'] || 3600
      let exp = iat + max
      let nonce = params.nonce
      let header = {alg, kid}
      let payload = {iss, sub, aud, exp, iat, nonce}
      let jwt = new IDToken({header, payload, key})

      // at_hash
      // c_hash

      // encode the JWT
      return jwt.encode().then(compact => {
        response['id_token'] = compact
        return response
      })
    }

    return response
  }

  /**
   * Include Session State
   */
  includeSessionState (response) {
    // ...
  }

  random (byteLen) {
    let value = crypto.getRandomValues(new Uint8Array(byteLen))
    return Buffer.from(value).toString('hex')
  }
}

/**
 * Export
 */
module.exports = AuthenticationRequest

