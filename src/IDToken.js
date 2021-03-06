/**
 * Local dependencies
 */
const crypto = require('@trust/webcrypto')
const base64url = require('base64url')
const {JWT} = require('@trust/jose')
const IDTokenSchema = require('./schemas/IDTokenSchema')

const DEFAULT_MAX_AGE = 3600  // Default ID token expiration, in seconds
const DEFAULT_SIG_ALGORITHM = 'RS256'

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
   *
   * @param provider {Provider} OIDC Identity Provider issuing the token
   * @param provider.issuer {string} Provider URI
   * @param provider.keys {KeyChain}
   *
   * @param options {Object}
   * @param options.aud {string|Array<string>} Audience for the token
   *   (such as the Relying Party client_id)
   * @param options.azp {string} Authorized party / Presenter (RP client_id)
   * @param options.sub {string} Subject id for the token (opaque, unique to
   *   the issuer)
   * @param options.nonce {string} Nonce generated by Relying Party
   *
   * Optional:
   * @param [options.alg] {string} Algorithm for signing the id token
   * @param [options.jti] {string} Unique JWT id (to prevent reuse)
   * @param [options.iat] {number} Issued at timestamp (in seconds)
   * @param [options.max] {number} Max token lifetime in seconds
   * @param [options.at_hash] {string} Access Token Hash
   * @param [options.c_hash] {string} Code hash
   * @param [options.cnf] {Object} Proof of Possession confirmation key, see
   *   https://tools.ietf.org/html/rfc7800#section-3.1
   *
   * @returns {IDToken} ID Token (JWT instance)
   */
  static issue (provider, options) {
    let { issuer, keys } = provider

    let { aud, azp, sub, nonce, at_hash, c_hash, cnf } = options

    let alg = options.alg || DEFAULT_SIG_ALGORITHM
    let jti = options.jti || IDToken.random(8)
    let iat = options.iat || Math.floor(Date.now() / 1000)
    let max = options.max || DEFAULT_MAX_AGE

    let exp = iat + max  // token expiration

    let iss = issuer
    let key = keys['id_token'].signing[alg].privateKey
    let kid = keys['id_token'].signing[alg].publicJwk.kid

    let header = { alg, kid }
    let payload = { iss, aud, azp, sub, exp, iat, jti, nonce }

    if (at_hash) { payload.at_hash = at_hash }
    if (c_hash) { payload.c_hash = c_hash }
    if (cnf) { payload.cnf = cnf }

    let jwt = new IDToken({ header, payload, key })

    return jwt
  }

  /**
   * issueForRequest
   */
  static issueForRequest (request, response) {
    let {params, code, provider, client, subject} = request

    let alg = client['id_token_signed_response_alg'] || DEFAULT_SIG_ALGORITHM
    let jti = IDToken.random(8)
    let iat = Math.floor(Date.now() / 1000)
    let aud, azp, sub, max, nonce

    // authentication request
    if (!code) {
      aud = client['client_id']
      azp = client['client_id']
      sub = subject['_id']
      max = parseInt(params['max_age']) || client['default_max_age'] || DEFAULT_MAX_AGE
      nonce = params.nonce

    // token request
    } else {
      aud = code.aud
      azp = code.azp || aud
      sub = code.sub
      max = parseInt(code['max']) || client['default_max_age'] || DEFAULT_MAX_AGE
      nonce = code.nonce
    }

    let len = alg.match(/(256|384|512)$/)[0]

    // generate hashes
    return Promise.all([
      IDToken.hashClaim(response['access_token'], len),
      IDToken.hashClaim(response['code'], len)
    ])

      // build the id_token
      .then(hashes => {
        let [at_hash, c_hash] = hashes

        let options = { alg, aud, azp, sub, iat, jti, nonce, at_hash, c_hash }

        if (request.cnfKey) {
          options.cnf = { jwk: request.cnfKey }
        }

        return IDToken.issue(provider, options)
      })

      // sign id token
      .then(jwt => jwt.encode())

      // add to response
      .then(compact => {
        response['id_token'] = compact
      })

      // resolve the response
      .then(() => response)
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
   * @returns {Promise<string>}
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

  static random (byteLen) {
    let value = crypto.getRandomValues(new Uint8Array(byteLen))
    return Buffer.from(value).toString('hex')
  }
}

IDToken.DEFAULT_MAX_AGE = DEFAULT_MAX_AGE
IDToken.DEFAULT_SIG_ALGORITHM = DEFAULT_SIG_ALGORITHM

/**
 * Export
 */
module.exports = IDToken
