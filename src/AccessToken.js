/**
 * Local dependencies
 */
const {JWT} = require('@trust/jose')
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

  /**
   * issue
   */
  static issue (request, response) {
    let {params, code, provider, client, subject} = request
    let {issuer, keys, backend} = provider

    let alg = client['access_token_signed_response_alg'] || 'RS256'
    let key = keys.token.signing[alg].privateKey
    let kid = keys.token.signing[alg].publicJwk.kid
    let iss = issuer
    let jti = request.random(8)
    let iat = Math.floor(Date.now() / 1000)
    let aud, sub, max, scope

    // authentication request
    if (!code) {
      aud = client['client_id']
      sub = subject['_id']
      max = parseInt(params['max_age']) || client['default_max_age'] || 3600
      scope = request.scope

    // token request
    } else {
      aud = code.aud
      sub = code.sub
      max = parseInt(code['max']) || client['default_max_age'] || 3600
      scope = code.scope
    }

    let exp = iat + max

    let header = {alg, kid}
    let payload = {iss, aud, sub, exp, iat, jti, scope}
    let jwt = new AccessToken({header, payload, key})

    // encode the JWT
    return jwt.encode()

      // set the response properties
      .then(compact => {
        response['access_token'] = compact
        response['token_type'] = 'Bearer'
        response['expires_in'] = max
      })

      // store access token by "jti" claim
      .then(() => {
        return provider.backend.put('tokens', `${jti}`, {header, payload})
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
          return provider.backend.put('refresh', `${refresh}`, {header, payload})
        }
      })

      // resolve the response
      .then(() => response)
  }
}

/**
 * Export
 */
module.exports = AccessToken
