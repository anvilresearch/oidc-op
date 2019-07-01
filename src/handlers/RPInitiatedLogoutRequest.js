'use strict'

/**
 * Dependencies
 * @ignore
 */
const qs = require('qs')
const BaseRequest = require('./BaseRequest')
const IDToken = require('../IDToken')

class RPInitiatedLogoutRequest extends BaseRequest {
  /**
   * RP Initiated Logout Request Handler
   *
   * @see https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
   * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPInitiated
   * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#RPInitiated
   *
   * @param req {HTTPRequest}
   * @param res {HTTPResponse}
   * @param provider {Provider}
   * @returns {Promise}
   */
  static handle (req, res, provider) {
    let { host } = provider
    let request = new RPInitiatedLogoutRequest(req, res, provider)

    return Promise
      .resolve(request)
      .then(request.validate)

      // From: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
      // At the logout endpoint, the OP SHOULD ask the End-User whether they want
      // to log out of the OP as well. If the End-User says "yes", then the OP
      // MUST log out the End-User.
      .then(host.logout)

      .then(request.redirectOrRespond.bind(request))
      .catch(request.error.bind(request))
  }

  /**
   * Constructor
   *
   * Session spec defines the following params to the RP Initiated Logout request:
   *   - `id_token_hint`
   *   - `post_logout_redirect_uri`
   *   - `state`
   *
   * @param req {HTTPRequest}
   * @param res {HTTPResponse}
   * @param provider {Provider}
   */
  constructor (req, res, provider) {
    super(req, res, provider)
    this.params = RPInitiatedLogoutRequest.getParams(this)
  }

  /**
   * validateIdTokenHint
   *
   * Validates the `id_token_hint` parameter
   *
   * RECOMMENDED. Previously issued ID Token passed to the logout endpoint as
   * a hint about the End-User's current authenticated session with the Client.
   * This is used as an indication of the identity of the End-User that the RP
   * is requesting be logged out by the OP. The OP *need not* be listed as an
   * audience of the ID Token when it is used as an `id_token_hint` value.
   *
   * @param request {RPInitiatedLogoutRequest}
   * @returns {Promise<RPInitiatedLogoutRequest>} Chainable
   */
  validateIdTokenHint (request) {
    let { provider, params } = request
    let { id_token_hint: hint } = params

    if (!hint) {
      return request
    }

    return IDToken.decode(hint)
      .then(decoded => {
        if (!decoded.resolveKeys(provider.keys.jwks)) {
          throw new Error('ID Token hint keys cannot be resolved')
        }

        return decoded.verify()
          .then(() => {
            request.params.decodedHint = decoded
            return request
          })
      })
  }

  /**
   * validatePostLogoutUri
   *
   * Validates that `post_logout_redirect_uri` has been registered
   *
   * The value MUST have been previously registered with the OP, either using
   * the `post_logout_redirect_uris` Registration parameter
   * or via another mechanism.
   *
   * Question: what's this about 'another mechanism'?
   *
   * @param request {RPInitiatedLogoutRequest}
   * @returns {Promise<RPInitiatedLogoutRequest>} Chainable
   */
  validatePostLogoutUri (request) {
    let { provider, params } = request
    let { post_logout_redirect_uri: uri, id_token_hint: hint } = params
    let { decodedHint } = params

    if (!uri) {
      return request
    }

    // Get the client from the ID Token Hint to validate that the
    // post logout redirect URI has been pre-registered
    let clientId = decodedHint.clientId

    return provider.backend.get('clients', cliendId)
      .then(client => {
        if (!client) {
          throw new Error('Invalid ID Token hint (client not found)')
        }

        // Check that the post logout uri has been registered
        if (!client['post_logout_redirect_uris'].includes(uri)) {
          throw new Error('post_logout_redirect_uri must be pre-registered')
        }

        // Valid
        return request
      })
  }

  /**
   * Validate
   *
   * @see https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
   *
   * @param request {RPInitiatedLogoutRequest}
   */
  validate (request) {
    /**
     * `state` parameter - no validation needed. Will be passed back to the RP
     * in the `redirectToRP()` step.
     */
    if (uri && !hint) {
      throw new Error('post_logout_redirect_uri requires an id_token_hint')
    }

    return Promise.resolve(request)
      .then(request.validateIdTokenHint)
      .then(request.validatePostLogoutUri)
  }

  /**
   * Redirect to RP or Respond
   *
   * In some cases, the RP will request that the End-User's User Agent to be
   * redirected back to the RP after a logout has been performed. Post-logout
   * redirection is only done when the logout is RP-initiated, in which case the
   * redirection target is the `post_logout_redirect_uri` query parameter value
   * used by the initiating RP; otherwise it is not done.
   *
   * @see https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout
   *
   * @returns {null}
   */
  redirectOrRespond () {
    let { params: { post_logout_redirect_uri: postLogoutRedirectUri } } = this
    if (postLogoutRedirectUri) {
      this.redirectToRP()
    } else {
      this.respond()
    }
  }

  /**
   * Redirect To RP
   *
   * Redirects the user-agent back to the RP, if requested (by the RP providing
   * a `post_logout_redirect_uri` parameter). Also passes through the `state`
   * parameter, if supplied by the RP.
   *
   * @returns {null}
   */
  redirectToRP () {
    let { res, params: { post_logout_redirect_uri: uri, state } } = this

    if (state) {
      let response = qs.stringify({ state })
      uri = `${uri}?${response}`
    }

    res.redirect(uri)  // 302 redirect
  }

  /**
   * Respond
   *
   * Responds to the RP Initiated Logout request with a 204 No Content, if the
   * RP did not supply a `post_logout_redirect_uri` parameter.
   *
   * @returns {null}
   */
  respond () {
    let { res } = this

    res.set({
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache'
    })

    res.status(204).send()
  }
}

module.exports = RPInitiatedLogoutRequest
