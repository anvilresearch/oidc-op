'use strict'

/**
 * Dependencies
 */
const {JSONDocument} = require('json-document')
const KeyChain = require('keychain')
const ProviderSchema = require('./schemas/ProviderSchema')
const AuthenticationRequest = require('./handlers/AuthenticationRequest')
const OpenIDConfigurationRequest = require('./handlers/OpenIDConfigurationRequest')
const DynamicRegistrationRequest = require('./handlers/DynamicRegistrationRequest')
const JWKSetRequest = require('./handlers/JWKSetRequest')
const TokenRequest = require('./handlers/TokenRequest')
const UserInfoRequest = require('./handlers/UserInfoRequest')

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
   * initializeKeyChain
   */
  initializeKeyChain () {
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
   * Authorize
   *
   * @param {HTTPRequest} req
   * @param {HTTPResponse} res
   */
  authorize (req, res) {
    AuthenticationRequest.handle(req, res, this)
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
