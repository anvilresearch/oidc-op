'use strict'

/**
 * Test dependencies
 */
const cwd = process.cwd()
const path = require('path')
const chai = require('chai')
const sinon = require('sinon')
const sinonChai = require('sinon-chai')

/**
 * Assertions
 */
chai.use(sinonChai)
chai.use(require('dirty-chai'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const Provider = require(path.join(cwd, 'src', 'Provider'))
const ProviderSchema = require(path.join(cwd, 'src', 'schemas', 'ProviderSchema'))
const AuthenticationRequest = require(path.join(cwd, 'src', 'handlers', 'AuthenticationRequest'))
const OpenIDConfigurationRequest = require(path.join(cwd, 'src', 'handlers', 'OpenIDConfigurationRequest'))
const DynamicRegistrationRequest = require(path.join(cwd, 'src', 'handlers', 'DynamicRegistrationRequest'))
const JWKSetRequest = require(path.join(cwd, 'src', 'handlers', 'JWKSetRequest'))
const TokenRequest = require(path.join(cwd, 'src', 'handlers', 'TokenRequest'))
const UserInfoRequest = require(path.join(cwd, 'src', 'handlers', 'UserInfoRequest'))
const RPInitiatedLogoutRequest = require(path.join(cwd, 'src', 'handlers', 'RPInitiatedLogoutRequest'))
const {JSONSchema} = require('@trust/json-document')

/**
 * Tests
 */
describe('OpenID Connect Provider', () => {

  /**
   * Schema
   */
  describe('schema', () => {
    it('should reference the OpenID Connect Provider Schema', () => {
      Provider.schema.should.equal(ProviderSchema)
    })

    it('should be an instance of JSONSchema', () => {
      ProviderSchema.should.be.an.instanceof(JSONSchema)
    })
  })

  /**
   * Constructor
   */
  describe('constructor', () => {
    it('should initialize default endpoints', () => {
      sinon.spy(Provider, 'initializeEndpoints')

      new Provider({ issuer: 'https://example.com' })

      expect(Provider.initializeEndpoints).to.have.been.called()
    })
  })

  /**
   * Validate
   */
  describe('validate', () => {
    it('should initialize based on the defined schema')
  })

  /**
   * Inject
   */
  describe('inject', () => {
    it('should set non-enumerable property', () => {
      let provider = new Provider({ issuer: 'https://forge.anvil.io' })
      expect(provider.injected).to.be.undefined()
      provider.inject({ injected: true })
      provider.injected.should.equal(true)
      Object.keys(provider).should.not.include('injected')
    })
  })

  /**
   * Authorize
   */
  describe('authorize endpoint', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(AuthenticationRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.authorize(req, res, provider)
    })

    after(() => {
      AuthenticationRequest.handle.restore()
    })

    it('should invoke the AuthenticationRequest handler', () => {
      AuthenticationRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })

  /**
   * Discover
   */
  describe('discover endpoint', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(OpenIDConfigurationRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.discover(req, res, provider)
    })

    after(() => {
      OpenIDConfigurationRequest.handle.restore()
    })

    it('should invoke the OpenIDConfigurationRequest handler', () => {
      OpenIDConfigurationRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })

  /**
   * JWKs
   */
  describe('jwks endpoint', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(JWKSetRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.jwks(req, res, provider)
    })

    after(() => {
      JWKSetRequest.handle.restore()
    })

    it('should invoke the JWKSetRequest handler', () => {
      JWKSetRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })

  /**
   * Register
   */
  describe('dynamic registration endpoint', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(DynamicRegistrationRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.register(req, res, provider)
    })

    after(() => {
      DynamicRegistrationRequest.handle.restore()
    })

    it('should invoke the DynamicRegistrationRequest handler', () => {
      DynamicRegistrationRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })

  /**
   * Token
   */
  describe('token endpoint', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(TokenRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.token(req, res, provider)
    })

    after(() => {
      TokenRequest.handle.restore()
    })

    it('should invoke the TokenRequest handler', () => {
      TokenRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })

  /**
   * UserInfo
   */
  describe('userinfo endpoint', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(UserInfoRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.userinfo(req, res, provider)
    })

    after(() => {
      UserInfoRequest.handle.restore()
    })

    it('should invoke the UserInfoRequest handler', () => {
      UserInfoRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })

  describe('logout', () => {
    let req, res, provider

    before(() => {
      req = {}
      res = {}
      sinon.stub(RPInitiatedLogoutRequest, 'handle')
      provider = new Provider({}, {}, {})
      provider.logout(req, res, provider)
    })

    after(() => {
      RPInitiatedLogoutRequest.handle.restore()
    })

    it('should invoke the RPInitiatedLogoutRequest handler', () => {
      RPInitiatedLogoutRequest.handle.should.have.been
        .calledWith(req, res, provider)
    })
  })
})
