/**
 * Dependencies
 */
const {JSONSchema} = require('@trust/json-document')

/**
 * AuthorizationCodeSchema
 */
const AuthorizationCodeSchema = new JSONSchema({
  properties: {
    code: {
      type: 'string'
    },

    sub: {
      type: 'string'
    },

    aud: {
      type: 'string'
    },

    redirect_uri: {
      type: 'string',
      format: 'uri'
    },

    exp: {
      type: 'integer'
    },

    max: {
      type: 'integer'
    },

    scope: {
      type: 'string'
    },

    nonce: {
      type: 'string'
    }

    // expires_at
    // client_id
    // redirect_uri
    // max_age
    // user_id
    // scope
    // used
    // nonce
  }
})

/**
 * Export
 */
module.exports = AuthorizationCodeSchema
