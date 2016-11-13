/**
 * Dependencies
 */
const {JSONDocument} = require('json-document')
const {AuthorizationCodeSchema} = require('./schemas')

/**
 * AuthorizationCode
 */
class AuthorizationCode extends JSONDocument {

  /**
   * schema
   */
  static get schema () {
    return AuthorizationCodeSchema
  }
}

/**
 * Export
 */
module.exports = AuthorizationCode
