'use strict'

/**
 * Dependencies
 * @ignore
 */
const {JWT} = require('@trust/jose')
const crypto = require('@trust/webcrypto')
const BaseRequest = require('./BaseRequest')
const Client = require('../Client')

/**
 * DynamicRegistrationRequest
 */
class DynamicRegistrationRequest extends BaseRequest {

  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    let request = new DynamicRegistrationRequest(req, res, provider)

    Promise.resolve(request)
      .then(request.validate)
      .then(request.register)
      .then(request.token)
      .then(request.respond)
      .catch(request.error.bind(request))
  }

  /**
   * Validate
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {DynamicRegistrationRequest}
   */
  validate (request) {
    let registration = request.req.body

    if (!registration) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing registration request body'
      })
    }

    // Return an explicit error on missing redirect_uris
    if (!registration.redirect_uris) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Missing redirect_uris parameter'
      })
    }

    // generate a client id unless one is provided
    if (!registration['client_id']) {
      registration['client_id'] = request.identifier()
    }

    // generate a client secret for non-implicit clients
    if (!request.implicit(registration)) {
      registration.client_secret = request.secret()
    }

    /**
     * TODO: Validate that the `frontchannel_logout_uri` domain and port is the same as one of the `redirect_uris` values
     * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
     *
     * The domain, port, and scheme of this URL MUST be the same as that of a
     * registered Redirection URI value.
     */

    // initialize and validate a client
    let client = new Client(registration)
    let validation = client.validate()

    if (!validation.valid) {
      return request.badRequest({
        error: 'invalid_request',
        error_description: 'Client validation error: ' + JSON.stringify(validation)
      })
    }

    request.client = client
    return request
  }

  /**
   * register
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {Promise}
   */
  register (request) {
    let backend = request.provider.backend
    let client = request.client
    let id = client['client_id']

    return backend.put('clients', id, client).then(client => request)
  }

  /**
   * token
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {Promise}
   */
  token (request) {
    let {provider, client} = request
    let {issuer, keys} = provider
    let alg = client['id_token_signed_response_alg']

    // create a registration access token
    let jwt = new JWT({
      header: {
        alg
      },
      payload: {
        iss: issuer,
        aud: client['client_id'],
        sub: client['client_id']
      },
      key: keys.register.signing[alg].privateKey
    })

    // sign the token
    return jwt.encode().then(compact => {
      request.compact = compact
      return request
    })
  }

  /**
   * respond
   *
   * @param {DynamicRegistrationRequest} request
   * @returns {Promise}
   */
  respond (request) {
    let {client, compact, provider, res} = request

    let response = Object.assign({}, client, {
      registration_access_token: compact,
      registration_client_uri: `${provider.issuer}/register/${client.client_id}`,
      client_id_issued_at: Math.floor(Date.now() / 1000)
    })

    if (client.client_secret) {
      response.client_secret_expires_at = 0
    }

    res.set({
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache'
    })

    res.status(201).json(response)
  }

  /**
   * identifier
   *
   * @returns {string}
   */
  identifier () {
    let value = crypto.getRandomValues(new Uint8Array(16))
    return Buffer.from(value).toString('hex')
  }

  /**
   * secret
   *
   * @returns {string}
   */
  secret () {
    let value = crypto.getRandomValues(new Uint8Array(16))
    return Buffer.from(value).toString('hex')
  }

  /**
   * implicit
   *
   * @param {Object} registration
   * @returns {Boolean}
   */
  implicit (registration) {
    let responseTypes = registration['response_types']

    return !!(responseTypes
      && responseTypes.length === 1
      && responseTypes[0] === 'id_token token')
  }
}

/**
 * Export
 */
module.exports = DynamicRegistrationRequest


