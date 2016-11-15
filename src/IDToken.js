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

  /**
   * issue
   */
  static issue (request, response) {
    let {params, code, provider, client, subject} = request
    let {issuer, keys, backend} = provider

    let alg = client['id_token_signed_response_alg'] || 'RS256'
    let key = keys['id_token'].signing[alg].privateKey
    let kid = keys['id_token'].signing[alg].publicJwk.kid
    let iss = issuer
    let jti = request.random()
    let iat = Math.floor(Date.now() / 1000)
    let aud, sub, max, nonce

    // authentication request
    if (!code) {
      aud = client['client_id']
      sub = subject['_id']
      //max = parseInt(params['max_age']) || client['default_max_age'] || 3600
      nonce = params.nonce

    // token request
    } else {
      aud = code.aud
      sub = code.sub
      //max = parseInt(code['max']) || client['default_max_age'] || 3600
      nonce = code.nonce
    }

    let exp = iat + max

    let header = {alg, kid}
    let payload = {iss, aud, sub, exp, iat, jti, nonce}
    let jwt = new IDToken({header, payload, key})

    return jwt.encode().then(compact => {
      response['id_token'] = compact
      return response
    })
  }
}

/**
 * Export
 */
module.exports = IDToken
