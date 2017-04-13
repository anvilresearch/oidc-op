'use strict'

/**
 * Dependencies
 */
const {JSONDocument} = require('@trust/json-document')
const KeyChain = require('@trust/keychain')
const ProviderSchema = require('./schemas/ProviderSchema')
const AuthenticationRequest = require('./handlers/AuthenticationRequest')
const OpenIDConfigurationRequest = require('./handlers/OpenIDConfigurationRequest')
const DynamicRegistrationRequest = require('./handlers/DynamicRegistrationRequest')
const JWKSetRequest = require('./handlers/JWKSetRequest')
const TokenRequest = require('./handlers/TokenRequest')
const UserInfoRequest = require('./handlers/UserInfoRequest')
const RPInitiatedLogoutRequest = require('./handlers/RPInitiatedLogoutRequest')

/**
 * OpenID Connect Provider
 */
class Provider extends JSONDocument {

  /**
   * constructor
   */
  constructor (data, options) {
    let {issuer} = data

    //assert(issuer, 'OpenID Provider must have an issuer')

    data['authorization_endpoint'] = `${issuer}/authorize`
    data['token_endpoint'] = `${issuer}/token`
    data['userinfo_endpoint'] = `${issuer}/userinfo`
    data['jwks_uri'] = `${issuer}/jwks`
    data['registration_endpoint'] = `${issuer}/register`
    data['check_session_iframe'] = `${issuer}/session`
    data['end_session_endpoint'] = `${issuer}/logout`

    super(data, options)
  }

  /**
   * from
   *
   * @param data {Object} Parsed JSON of a serialized Provider
   * @returns {Promise<Provider>}
   */
  static from (data) {
    let provider = new Provider(data)

    let validation = provider.validate()

    // schema validation
    if (!validation.valid) {
      return Promise.reject(validation)
    }

    return KeyChain.restore(data.keys)
      .then(keychain => {
        provider.keys = keychain

        return provider
      })
  }

  /**
   * initializeKeyChain
   *
   * @param data {Object} Parsed JSON of a serialized provider's .keys property
   * @returns {Promise<Provider>} Resolves to self, chainable
   */
  initializeKeyChain (data) {
    if (!data) {
      return this.generateKeyChain()
    }

    return this.importKeyChain(data)
  }

  /**
   * generateKeyChain
   */
  generateKeyChain () {
    let modulusLength = 2048

    let descriptor = {
      id_token: {
        signing: {
          RS256: { alg: 'RS256', modulusLength },
          RS384: { alg: 'RS384', modulusLength },
          RS512: { alg: 'RS512', modulusLength }
        },
        encryption: {
          // ?
        }
      },
      token: {
        signing: {
          RS256: { alg: 'RS256', modulusLength },
          RS384: { alg: 'RS384', modulusLength },
          RS512: { alg: 'RS512', modulusLength }
        },
        encryption: {}
      },
      userinfo: {
        encryption: {}
      },
      register: {
        signing: {
          RS256: { alg: 'RS256', modulusLength }
        }
      }
    }

    this.keys = new KeyChain(descriptor)
    return this.keys.rotate()
  }

  /**
   * importKeyChain
   *
   * @param data {Object} Parsed JSON of a serialized provider's .keys property
   * @returns {Promise<Provider>} Resolves to self, chainable
   */
  importKeyChain (data) {
    if (!data) {
      return Promise.reject(new Error('Cannot import empty keychain'))
    }

    return KeyChain.restore(data)
      .then(keychain => {
        this.keys = keychain

        return this
      })
  }

  /**
   * openidConfiguration
   */
  get openidConfiguration () {
    return JSON.stringify(this, Object.keys(ProviderSchema.properties))
  }

  /**
   * jwkSet
   */
  get jwkSet () {
    return this.keys.jwkSet
  }

  /**
   * Schema
   *
   * @returns {JSONSchema}
   */
  static get schema () {
    return ProviderSchema
  }

  /**
   * inject
   */
  inject (properties) {
    Object.keys(properties).forEach(key => {
      let value = properties[key]

      Object.defineProperty(this, key, {
        enumerable: false,
        value
      })
    })
  }

  /**
   * Authorize
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  authorize (req, res) {
    AuthenticationRequest.handle(req, res, this)
  }

  /**
   * Logout
   *
   * Bound to the OP's `end_session_endpoint` uri
   *
   * @param req {HTTPRequest}
   * @param res {HTTPResponse}
   */
  logout (req, res) {
    RPInitiatedLogoutRequest.handle(req, res, this)
  }

  /**
   * Discover
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  discover (req, res) {
    OpenIDConfigurationRequest.handle(req, res, this)
  }

  /**
   * JWKs
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  jwks (req, res) {
    JWKSetRequest.handle(req, res, this)
  }

  /**
   * Register
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  register (req, res) {
    DynamicRegistrationRequest.handle(req, res, this)
  }

  /**
   * Token
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  token (req, res) {
    TokenRequest.handle(req, res, this)
  }

  /**
   * UserInfo
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  userinfo (req, res) {
    UserInfoRequest.handle(req, res, this)
  }
}

/**
 * Export
 */
module.exports = Provider
