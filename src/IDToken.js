/**
 * Local dependencies
 */
const {JWT} = require('jose')
const IDTokenSchema = require('./schemas/IDTokenSchema')

/**
 * IDToken
 */
class IDToken extends JWT {

  /**
   * Schema
   */
  static get schema () {
    return IDTokenSchema
  }
}

/**
 * Export
 */
module.exports = IDToken
