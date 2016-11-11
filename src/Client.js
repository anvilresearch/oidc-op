/**
 * Dependencies
 */
const {JSONDocument} = require('json-document')
const ClientSchema = require('./schemas/ClientSchema')

/**
 * Client
 */
class Client extends JSONDocument {

  /**
   * schema
   */
  static get schema () {
    return ClientSchema
  }
}

/**
 * Export
 */
module.exports = Client
