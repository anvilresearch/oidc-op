/**
 * Local dependencies
 */
const crypto = require('webcrypto')
const base64url = require('base64url')
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
    let jti = request.random(8)
    let iat = Math.floor(Date.now() / 1000)
    let aud, sub, max, nonce

    // authentication request
    if (!code) {
      aud = client['client_id']
      sub = subject['_id']
      max = parseInt(params['max_age']) || client['default_max_age'] || 3600
      nonce = params.nonce

    // token request
    } else {
      aud = code.aud
      sub = code.sub
      max = parseInt(code['max']) || client['default_max_age'] || 3600
      nonce = code.nonce
    }

    let exp = iat + max

    let len = alg.match(/(256|384|512)$/)[0]

    // generate
    return Promise.all([
      IDToken.hashClaim(response['access_token'], len),
      IDToken.hashClaim(response['code'], len)
    ])

    // build the id_token
    .then(hashes => {
      let [at_hash, c_hash] = hashes
      let header = {alg, kid}
      let payload = {iss, aud, sub, exp, iat, jti, nonce, at_hash, c_hash}
      return new IDToken({header, payload, key})
    })

    // sign id token and add to response
    .then(jwt => {
      return jwt.encode().then(compact => {
        response['id_token'] = compact
        return response
      })
    })
  }

  /**
   * hashClaim
   *
   * @description
   * Create a hash for at_hash or c_hash claim
   *
   * @param {string} token
   * @param {string} hashLength
   *
   * @returns {Promise}
   */
  static hashClaim (value, hashLength) {
    if (value) {
      let alg = { name: `SHA-${hashLength}`}
      let octets = new Buffer(value, 'ascii')

      return crypto.subtle.digest(alg, new Uint8Array(octets)).then(digest => {
        let hash = Buffer.from(digest)
        let half = hash.slice(0, hash.byteLength / 2)
        return base64url(half)
      })
    }
  }
}

/**
 * Export
 */
module.exports = IDToken
