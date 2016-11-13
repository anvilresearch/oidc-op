/**
 * Local dependencies
 */
const {JWT} = require('jose')
const AccessTokenSchema = require('./schemas/AccessTokenSchema')

/**
 * AccessToken
 */
class AccessToken extends JWT {

  /**
   * Schema
   */
  static get schema () {
    return AccessTokenSchema
  }
}

/**
 * Export
 */
module.exports = AccessToken
