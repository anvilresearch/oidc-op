'use strict'

/**
 * Dependencies
 * @ignore
 */
const crypto = require('@trust/webcrypto')
const qs = require('qs')

const HandledError = require('../errors/HandledError')

/**
 * Request Parameter Mapping
 */
const PARAMS = { 'GET': 'query', 'POST': 'body' }

/**
 * Response Mode Mapping
 */
const MODES = { 'query': '?', 'fragment': '#' }

/**
 * BaseRequest
 *
 * @class
 * Abstract class for implementing OpenID Connect request handlers.
 */
class BaseRequest {

  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    throw new Error('Handle must be implemented by BaseRequest subclass')
  }

  /**
   * Constructor
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  constructor (req, res, provider) {
    this.req = req
    this.res = res
    this.provider = provider
    this.host = provider.host
  }

  /**
   * Get Params
   *
   * @param {BaseRequest} request
   * @returns {Object}
   */
  static getParams (request) {
    let { req } = request
    return req[PARAMS[req.method]] || {}
  }

  /**
   * Get Response Types
   *
   * @param {BaseRequest} request
   * @returns {Array}
   */
  static getResponseTypes (request) {
    let { params: { response_type: type } } = request
    return (typeof type === 'string') ? type.split(' ') : []
  }

  /**
   * Get Response Mode
   *
   * @param {BaseRequest} request
   * @returns {string}
   */
  static getResponseMode (request) {
    let mode
    let { params } = request || {}
    let { response_mode: responseMode, response_type: responseType } = params

    if (responseMode) {
      mode = MODES[responseMode]
    } else if (responseType === 'code' || responseType === 'none') {
      mode = '?'
    } else {
      mode = '#'
    }

    return mode
  }

  /**
   * 302 Redirect Response
   */
  redirect (data) {
    let { res, params: { redirect_uri: uri, state }, responseMode } = this

    if (state) {
      data.state = state
    }

    let response = qs.stringify(data)
    res.redirect(`${uri}${responseMode}${response}`)

    let error = new HandledError('302 Redirect')

    if (data.error) {
      error.error = data.error
      error.error_description = data.error_description
    }

    throw error
  }

  /**
   * 401 Unauthorized Response
   */
  unauthorized (err) {
    let { res } = this
    let { realm, error, error_description: description } = err

    res.set({
      'WWW-Authenticate':
      `Bearer realm=${realm}, error=${error}, error_description=${description}`
    })

    res.status(401).send('Unauthorized')

    throw new HandledError('401 Unauthorized')
  }

  /**
   * 403 Forbidden Response
   *
   * @param params {Object}
   * @param params.error {string}
   * @param params.error_description {string}
   */
  forbidden (params) {
    let {res} = this

    res.status(403).send('Forbidden')

    let error = new HandledError('403 Forbidden')
    error.error = params.error
    error.error_description = params.error_description
    throw error
  }

  /**
   * 400 Bad Request Response
   *
   * @param params {Object}
   * @param params.error {string}
   * @param params.error_description {string}
   */
  badRequest (params) {
    let {res} = this

    res.set({
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache'
    })

    res.status(400).json(params)

    let error = new HandledError('400 Bad Request')

    error.error = params.error || 'invalid_request'
    error.error_description = params.error_description

    throw error
  }

  /**
   * Serves as a general purpose error handler for `.catch()` clauses in
   * Promise chains. Example usage:
   *
   *   ```
   *   return Promise.resolve(request)
   *     .then(request.validate)
   *     .then(request.stepOne)
   *     .then(request.stepTwo)  // etc.
   *     .catch(request.error.bind(request))
   *   ```
   *
   * If at any point (say, in `validate()` or `stepOne()`) the code needs to
   * break out of that promise chain intentionally, it should throw a
   * `HandledError`. For example:
   *
   *   ```
   *   throw new HandledError('400 Bad Request')
   *   ```
   *
   * @param error {HandledError|Error}
   */
  error (error) {
    if (!error.handled) {
      this.internalServerError(error)
    }
  }

  /**
   * Internal Server Error
   */
  internalServerError (err) {
    // TODO: Debug logging here
    let {res} = this
    res.status(500).send('Internal Server Error')
  }



  /**
   * TODO
   * This doesn't belong here.
   */
  random (byteLen) {
    let value = crypto.getRandomValues(new Uint8Array(byteLen))
    return Buffer.from(value).toString('hex')
  }
}

/**
 * Export
 */
module.exports = BaseRequest

