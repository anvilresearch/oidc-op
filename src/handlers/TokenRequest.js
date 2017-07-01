'use strict'

/**
 * Dependencies
 * @ignore
 */
const BaseRequest = require('./BaseRequest')
const AccessToken = require('../AccessToken')
const AuthorizationCode = require('../AuthorizationCode')
const IDToken = require('../IDToken')

/**
 * TokenRequest
 */
class TokenRequest extends BaseRequest {

  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    let request = new TokenRequest(req, res, provider)

    Promise
      .resolve(request)
      .then(request.validate)
      .then(request.authenticateClient)
      .then(request.verifyAuthorizationCode)
      .then(request.grant)
      .catch(request.error.bind(request))
  }

  /**
   * Constructor
   */
  constructor (req, res, provider) {
    super(req, res, provider)
    this.params = TokenRequest.getParams(this)
    this.grantType = TokenRequest.getGrantType(this)
  }

  /**
   * Get Grant Type
   *
   * @param {TokenRequest} request
   * @return {string}
   */
  static getGrantType (request) {
    let {params} = request
    return params.grant_type
  }

  /**
   * Validate Request
   *
   * @param request {TokenRequest}
   * @returns {Promise<TokenRequest>}
   */
  validate (request) {
    let {params,provider} = request

    // MISSING GRANT TYPE
    if (!params.grant_type) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing grant type'
      })
    }

    // UNSUPPORTED GRANT TYPE
    if (!request.supportedGrantType()) {
      return request.badRequest({
        error: 'unsupported_grant_type',
        error_description: 'Unsupported grant type'
      })
    }

    // MISSING AUTHORIZATION CODE
    if (params.grant_type === 'authorization_code' && !params.code) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing authorization code'
      })
    }

    // MISSING REDIRECT URI
    if (params.grant_type === 'authorization_code' && !params.redirect_uri) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect uri'
      })
    }

    // MISSING REFRESH TOKEN
    if (params.grant_type === 'refresh_token' && !params.refresh_token) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing refresh token'
      })
    }

    return Promise.resolve(request)
  }

  /**
   * Supported Grant Type
   * @returns {Boolean}
   */
  supportedGrantType () {
    let {params,provider} = this
    let supportedGrantTypes = provider.grant_types_supported
    let requestedGrantType = params.grant_type

    return supportedGrantTypes.includes(requestedGrantType)
  }

  /**
   * Authenticate Client
   *
   * @param request {TokenRequest}
   * @returns {Promise<TokenRequest>}
   */
  authenticateClient (request) {
    let method
    let {req} = request

    // Use HTTP Basic Authentication Method
    if (req.headers && req.headers.authorization) {
      method = 'clientSecretBasic'
    }

    // Use HTTP Post Authentication Method
    if (req.body && req.body.client_secret) {
      // Fail if multiple authentication methods are attempted
      if (method) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      }

      method = 'clientSecretPost'
    }

    // Use Client JWT Authentication Method
    if (req.body && req.body.client_assertion_type) {
      var type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

      // Fail if multiple authentication methods are attempted
      if (method) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      }

      // Invalid client assertion type
      if (req.body.client_assertion_type !== type) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Invalid client assertion type'
        })
      }

      // Missing client assertion
      if (!req.body.client_assertion) {
        return request.badRequest({
          error: 'unauthorized_client',
          error_description: 'Missing client assertion'
        })
      }

      method = 'clientSecretJWT'
    }

    // Missing authentication parameters
    if (!method) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    // Apply the appropriate authentication method
    return request[method](request)
  }

  /**
   * Client Secret Basic Authentication
   *
   * @description
   * HTTP Basic Authentication of client using client_id and client_secret as
   * username and password.
   * @param {TokenRequest} request
   * @returns {Promise<TokenRequest>}
   */
  clientSecretBasic (request) {
    let {req:{headers},provider} = request
    let authorization = headers.authorization.split(' ')
    let scheme = authorization[0]
    let credentials = new Buffer(authorization[1], 'base64')
      .toString('ascii')
      .split(':')
    let [id, secret] = credentials

   // MALFORMED CREDENTIALS
    if (credentials.length !== 2) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Malformed HTTP Basic credentials'
      })
    }

    // INVALID AUTHORIZATION SCHEME
    if (!/^Basic$/i.test(scheme)) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Invalid authorization scheme'
      })
    }

    // MISSING CREDENTIALS
    if (!id || !secret) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    return provider.backend.get('clients', id).then(client => {

      // UNKNOWN CLIENT
      if (!client) {
        return request.unauthorized({
          error: 'unauthorized_client',
          error_description: 'Unknown client identifier'
        })
      }

      // MISMATCHING SECRET
      if (client.client_secret !== secret) {
        return request.unauthorized({
          error: 'unauthorized_client',
          error_description: 'Mismatching client secret'
        })
      }

      request.client = client
      return request
    })
  }

  /**
   * Client Secret Post
   *
   * @description
   * Authentication of client using client_id and client_secret as HTTP POST
   * body parameters.
   * @param {TokenRequest} request
   * @returns {Promise<TokenRequest>}
   */
  clientSecretPost (request) {
    let {params: {client_id: id, client_secret: secret}, provider} = request

    // MISSING CREDENTIALS
    if (!id || !secret) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Missing client credentials'
      })
    }

    return new Promise((resolve, reject) => {
      provider.backend.get(id).then(client => {

        // UNKNOWN CLIENT
        if (!client) {
          return request.unauthorized({
            error: 'unauthorized_client',
            error_description: 'Unknown client identifier'
          })
        }

        // MISMATCHING SECRET
        if (client.client_secret !== secret) {
          return request.unauthorized({
            error: 'unauthorized_client',
            error_description: 'Mismatching client secret'
          })
        }

        resolve(request)
      })
    })
  }

  /**
   * Client Secret JWT Authentication
   *
   * TODO RTFS
   * @param request {TokenRequest}
   * @returns {Promise<TokenRequest>}
   */
  clientSecretJWT (request) {
    let { req: { body: { client_assertion: jwt } }, provider} = request
    let payloadB64u = jwt.split('.')[1]
    let payload = JSON.parse(base64url.decode(payloadB64u))

    if (!payload || !payload.sub) {
      return request.badRequest({
        error: 'unauthorized_client',
        error_description: 'Cannot extract client id from JWT'
      })
    }

    return new Promise((resolve, reject) => {
      provider.getClient(payload.sub).then(client => {

        if (!client) {
          return request.badRequest({
            error: 'unauthorized_client',
            error_description: 'Unknown client'
          })
        }

        if (!client.client_secret) {
          return request.badRequest({
            error: 'unauthorized_client',
            error_description: 'Missing client secret'
          })
        }

        let token = JWT.decode(jwt, client.client_secret)

        if (!token || token instanceof Error) {
          return request.badRequest({
            error: 'unauthorized_client',
            error_description: 'Invalid client JWT'
          })
        }

        // TODO validate the payload

        resolve(request)
      })
    })
  }

  /**
   * Private Key JWT Authentication
   */
  privateKeyJWT () {}

  /**
   * None Authentication
   */
  none () {}

  /**
   * Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  grant (request) {
    let {grantType} = request

    if (grantType === 'authorization_code') {
      return request.authorizationCodeGrant(request)
    }

    if (grantType === 'refresh_token') {
      return request.refreshTokenGrant(request)
    }

    if (grantType === 'client_credentials') {
      return request.clientCredentialsGrant(request)
    }

    // THIS IS SERIOUS TROUBLE
    // REQUEST VALIDATION SHOULD FILTER OUT
    // UNSUPPORTED GRANT TYPES BEFORE WE ARRIVE
    // HERE.
    throw new Error('Unsupported response type')
  }

  /**
   * Authorization Code Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  authorizationCodeGrant (request) {
    return Promise.resolve({})
      .then(response => request.includeAccessToken(response))
      .then(response => request.includeIDToken(response))
      .then(response => {
        request.res.json(response)
      })
  }

  /**
   * includeAccessToken
   */
  includeAccessToken (response) {
    return AccessToken.issueForRequest(this, response)
  }

  /**
   * includeIDToken
   */
  includeIDToken (response) {
    return IDToken.issue(this, response)
  }

  /**
   * Refresh Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Object>} Resolves to response object
   */
  refreshTokenGrant (request) {
    // TODO: I don't think this.tokenResponse is implemented..
    return AccessToken.refresh(request).then(this.tokenResponse)
  }

  /**
   * OAuth 2.0 Client Credentials Grant
   *
   * @param {TokenRequest} request
   * @returns {Promise<Null>}
   */
  clientCredentialsGrant (request) {
    let {res, client: { default_max_age: expires } } = request

    return AccessToken.issueForRequest(request, res).then(token => {
      let response = {}

      res.set({
        'Cache-Control': 'no-store',
        'Pragma': 'no-cache'
      })

      response.access_token = token
      response.token_type = 'Bearer'
      if (expires) {
        response.expires_in = expires
      }

      res.json(response)
    })
  }

  /**
   * Verify Authorization Code
   * @param request {TokenRequest}
   * @returns {TokenRequest}
   */
  verifyAuthorizationCode (request) {
    let {params, client, provider, grantType} = request

    if (grantType === 'authorization_code') {
      return provider.backend.get('codes', params.code).then(authorizationCode => {

        // UNKNOWN AUTHORIZATION CODE
        if (!authorizationCode) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Authorization not found'
          })
        }

        // AUTHORIZATION CODE HAS BEEN PREVIOUSLY USED
        if (authorizationCode.used === true) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Authorization code invalid'
          })
        }

        // AUTHORIZATION CODE IS EXPIRED
        if (authorizationCode.exp < Math.floor(Date.now() / 1000)) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Authorization code expired'
          })
        }

        // MISMATCHING REDIRECT URI
        if (authorizationCode.redirect_uri !== params.redirect_uri) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Mismatching redirect uri'
          })
        }

        // MISMATCHING CLIENT ID
        if (authorizationCode.aud !== client.client_id) {
          return request.badRequest({
            error: 'invalid_grant',
            error_description: 'Mismatching client id'
          })
        }

        // TODO mismatching user id?

        request.code = authorizationCode

        // TODO UPDATE AUTHORIZATION CODE TO REFLECT THAT IT'S BEEN USED
        //authorizationCode.use().then(() => Promise.resolve(request))
        return request
      })
    }

    return Promise.resolve(request)
  }
}

/**
 * Export
 */
module.exports = TokenRequest


