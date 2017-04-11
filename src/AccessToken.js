/**
 * Local dependencies
 */
const {JWT} = require('jose')
const crypto = require('webcrypto')
const AccessTokenSchema = require('./schemas/AccessTokenSchema')

const DEFAULT_MAX_AGE = 3600  // Default Access token expiration, in seconds
const DEFAULT_SIG_ALGORITHM = 'RS256'

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

  /**
   * @param options {Object}
   *
   * Required:
   * @param provider {Provider} OIDC Identity Provider issuing the token
   * @param provider.issuer {string} Provider URI
   * @param provider.keys
   *
   * @param options.aud {string} Audience for the token (client_id, etc)
   * @param options.sub {string} Subject id for the token
   * @param options.scope {string} OAuth2 scope
   *
   * Optional:
   * @param [options.alg] {string} Algorithm for signing the access token
   * @param [options.jti] {string} Unique JWT id (to prevent reuse)
   * @param [options.iat] {number} Issued at timestamp (in seconds)
   * @param [options.max] {number} Max token lifetime in seconds
   *
   * @returns {JWT} Access token (JWT instance)
   */
  static issue (provider, options) {
    let { issuer, keys } = provider

    let { aud, sub, scope } = options

    let alg = options.alg || DEFAULT_SIG_ALGORITHM
    let jti = options.jti || AccessToken.random(8)
    let iat = options.iat || Math.floor(Date.now() / 1000)
    let max = options.max || DEFAULT_MAX_AGE

    let exp = iat + max  // token expiration

    let iss = issuer
    let key = keys.token.signing[alg].privateKey
    let kid = keys.token.signing[alg].publicJwk.kid

    let header = { alg, kid }
    let payload = { iss, aud, sub, exp, iat, jti, scope }
    let jwt = new AccessToken({ header, payload, key })

    return jwt
  }

  /**
   * issue
   */
  static issueForRequest (request, response) {
    let { params, code, provider, client, subject } = request

    let alg = client['access_token_signed_response_alg'] || DEFAULT_SIG_ALGORITHM
    let jti = AccessToken.random(8)
    let iat = Math.floor(Date.now() / 1000)
    let aud, sub, max, scope

    // authentication request
    if (!code) {
      aud = client['client_id']
      sub = subject['_id']
      max = parseInt(params['max_age']) || client['default_max_age'] || DEFAULT_MAX_AGE
      scope = request.scope

    // token request
    } else {
      aud = code.aud
      sub = code.sub
      max = parseInt(code['max']) || client['default_max_age'] || DEFAULT_MAX_AGE
      scope = code.scope
    }

    let options = { aud, sub, scope, alg, jti, iat, max }

    let header, payload

    return Promise.resolve()
      .then(() => AccessToken.issue(provider, options))

      .then(jwt => {
        header = jwt.header
        payload = jwt.payload

        return jwt.encode()
      })

      // set the response properties
      .then(compact => {
        response['access_token'] = compact
        response['token_type'] = 'Bearer'
        response['expires_in'] = max
      })

      // store access token by "jti" claim
      .then(() => {
        return provider.backend.put('tokens', `${jti}`, { header, payload })
      })

      // store access token by "refresh_token", if applicable
      .then(() => {
        let responseTypes = request.responseTypes || []
        let refresh

        if (code || responseTypes.includes('code')) {
          refresh = request.random(16)
        }

        if (refresh) {
          response['refresh_token'] = refresh
          return provider.backend.put('refresh', `${refresh}`, { header, payload })
        }
      })

      // resolve the response
      .then(() => response)
      .catch(console.error.bind(console))
  }

  static random (byteLen) {
    let value = crypto.getRandomValues(new Uint8Array(byteLen))
    return Buffer.from(value).toString('hex')
  }
}

/**
 * Export
 */
module.exports = AccessToken
