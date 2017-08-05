/**
 * Local dependencies
 */
const {JWTSchema, JWKSchema} = require('@trust/jose')

/**
 * AccessTokenSchema
 */
const AccessTokenSchema = JWTSchema.extend({
  properties: {
    payload: {
      properties: {
        /**
         * cnf
         * OPTIONAL. Proof of Possession Confirmation Claim
         * @see https://tools.ietf.org/html/rfc7800#section-3.1
         *
         * The "cnf" claim value MUST represent only a single proof-of-
         * possession key; thus, at most one of the "jwk", "jwe", and "jku" (JWK
         * Set URL) confirmation values defined below may be present.
         */
        cnf: {
          type: 'object',

          properties: {
            jwk: JWKSchema
          }

          // TODO: Implement the jku and jwe cases
          // oneOf: [
          //   // jku
          //   {
          //     properties: {
          //       jku: { type: 'string', format: 'uri' }
          //     },
          //     required: ['jku']
          //   },
          //   // jwk
          //   {
          //     properties: {
          //       jwk: JWKSchema
          //     },
          //     required: ['jwk']
          //   },
          //   // jwe
          //   {
          //     properties: {
          //       jwe: { type: 'object' }
          //     },
          //     required: ['jwe']
          //   }
          // ]
        },

        /**
         * scope
         */
        scope: {
          type: ['array', 'string'],
          items: { type: 'string' }
        }
      }
    }
  }
})

/**
 * Export
 */
module.exports = AccessTokenSchema
