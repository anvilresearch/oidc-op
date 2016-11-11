'use strict'

/**
 * Dependencies
 * @ignore
 */
const BaseRequest = require('./BaseRequest')

/**
 * JWKSetRequest
 */
class JWKSetRequest extends BaseRequest {

  /**
   * Request Handler
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   * @param {Provider} provider
   */
  static handle (req, res, provider) {
    res.type('json')
    res.send(provider.jwkSet)
  }
}

/**
 * Export
 */
module.exports = JWKSetRequest


