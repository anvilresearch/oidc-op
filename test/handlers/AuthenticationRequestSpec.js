'use strict'

/**
 * Test dependencies
 */
const cwd = process.cwd()
const path = require('path')
const fs = require('fs')
const chai = require('chai')
const sinon = require('sinon')
const HttpMocks = require('node-mocks-http')
const MemoryStore = require(path.join(cwd, 'test', 'backends', 'MemoryStore'))
const { JWT } = require('@trust/jose')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.use(require('sinon-chai'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const AuthenticationRequest = require(path.join(cwd, 'src', 'handlers', 'AuthenticationRequest'))
const AccessToken = require(path.join(cwd, 'src', 'AccessToken'))
const IDToken = require(path.join(cwd, 'src', 'IDToken'))
const Provider = require(path.join(cwd, 'src', 'Provider'))

/**
 * Tests
 */
describe('AuthenticationRequest', () => {
  const host = {
    authenticate: (request) => {
      request.subject = { '_id': 'user1' }
      return request
    },
    obtainConsent: (request) => {
      request.consent = true
      return request
    }
  }
  let provider, params, req, res, request

  before(function () {
    this.timeout(5000)

    let configPath = path.join(__dirname, '..', 'config', 'provider.json')

    let storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))

    provider = new Provider(storedConfig)

    provider.inject({ host })
    provider.inject({ backend: new MemoryStore() })

    return provider.initializeKeyChain(provider.keys)
  })

  beforeEach(() => {
    res = HttpMocks.createResponse()
    params = {}
    req = HttpMocks.createRequest({ method: 'GET', query: params })
    provider.backend.data = {}
  })

  /**
   * Handle
   */
  describe('handle', () => {
    let client = {
      redirect_uris: 'https://example.com/callback',
      client_id: 'uuid'
    }
    let params = {
      client_id: 'uuid',
      redirect_uri: 'https://example.com/callback',
      response_type: 'id_token token',
      scope: 'openid',
      nonce: 'n0nc3'
    }

    beforeEach(() => {
      provider.backend.data.clients = {}
      provider.backend.put('clients', 'uuid', client)
    })

    it('should create and execute an AuthenticationRequest', () => {
      req = HttpMocks.createRequest({ method: 'GET', query: params })

      return AuthenticationRequest.handle(req, res, provider)
        .then(() => {
          let redirectUrl = res._getRedirectUrl()
          expect(redirectUrl.startsWith('https://example.com/callback#access_token'))
            .to.be.true()

          expect(res._getStatusCode()).to.equal(302)
        })
    })
  })

  /**
   * Constructor
   */
  describe('constructor', () => {
    beforeEach(() => {
      params = { response_type: 'code' }
    })

    it('should set "params" from request query', () => {
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)
      request.params.should.equal(params)
    })

    it('should set "params" from request body', () => {
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)
      request.params.should.equal(params)
    })

    it('should set "responseTypes"', () => {
      params = { response_type: 'code id_token token' }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)
      request.responseTypes.should.eql([ 'code', 'id_token', 'token' ])
    })

    it('should set "responseMode" default', () => {
      let req = { method: 'GET', query: params }
      let request = new AuthenticationRequest(req, res, provider)
      request.responseMode.should.eql('?')
    })

    it('should set "responseMode" explicitly', () => {
      let req = {
        method: 'GET',
        query: {
          response_type: 'id_token token',
          response_mode: 'query'
        }
      }

      let request = new AuthenticationRequest(req, res, provider)
      request.responseMode.should.eql('?')
    })
  })

  describe('loadClient', () => {
    const clientId = 'https://app.com'
    let client

    beforeEach(() => {
      client = { client_id: clientId }
      params = { client_id: clientId, response_type: 'id_token token' }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      request = new AuthenticationRequest(req, res, provider)
      provider.backend.get = sinon.stub().withArgs('clients', clientId)
        .resolves(client)
    })

    it('should load and set on the request the client for the given client_id', () => {
      return request.loadClient(request)
        .then(returnedRequest => {
          expect(returnedRequest.client).to.equal(client)
        })
    })

    it('should pass through the request if no client_id present in params', () => {
      delete request.params['client_id']

      return request.loadClient(request)
        .then(returnedRequest => {
          expect(returnedRequest).to.equal(request)
          expect(returnedRequest.client).to.be.undefined()
        })
    })

    it('should pass through the request if no client is found for the client_id', () => {
      request.provider.backend.get = sinon.stub().resolves(null)

      return request.loadClient(request)
        .then(returnedRequest => {
          expect(returnedRequest).to.equal(request)
          expect(returnedRequest.client).to.be.null()
        })
    })
  })

  /**
   * Supported Response Types
   */
  describe('supportedResponseType', () => {
    let provider

    beforeEach(() => {
      provider = { host, response_types_supported: ['code id_token'] }
    })

    it('should return true with a supported response type parameter', () => {
      let params = { response_type: 'code id_token' }
      let req = { method: 'GET', query: params }
      let request = new AuthenticationRequest(req, res, provider)
      request.supportedResponseType().should.equal(true)
    })

    it('should return false with an unsupported response type parameter', () => {
      let params = { response_type: 'code id_token token' }
      let req = { method: 'GET', query: params }
      let request = new AuthenticationRequest(req, res, provider)
      request.supportedResponseType().should.equal(false)
    })
  })

  /**
   * Supported Response Mode
   */
  describe('supportedResponseMode', () => {
    let provider

    beforeEach(() => {
      provider = { host, response_modes_supported: ['query', 'fragment'] }
    })

    it('should return true with an undefined response mode parameter', () => {
      let req = { method: 'GET', query: {} }
      let request = new AuthenticationRequest(req, res, provider)
      request.supportedResponseMode().should.equal(true)
    })

    it('should return true with a supported response mode parameter', () => {
      let params = { response_mode: 'fragment' }
      let req = { method: 'GET', query: params }
      let request = new AuthenticationRequest(req, res, provider)
      request.supportedResponseMode().should.equal(true)
    })

    it('should return false with an unsupported response mode parameter', () => {
      let params = { response_mode: 'unsupported' }
      let req = { method: 'GET', query: params }
      let request = new AuthenticationRequest(req, res, provider)
      request.supportedResponseMode().should.equal(false)
    })
  })

  /**
   * Required Nonce Provided
   */
  describe('requiredNonceProvided', () => {
    it('should return true when nonce is not required', () => {
      let req = { method: 'GET', query: { response_type: 'code' } }
      let request = new AuthenticationRequest(req, {}, { host: {} })
      request.requiredNonceProvided().should.equal(true)
    })

    it('should return true when nonce is required and provided', () => {
      let req = {
        method: 'GET',
        query: {
          response_type: 'id_token token',
          nonce: 'n0nc3'
        }
      }

      let request = new AuthenticationRequest(req, {}, { host: {} })
      request.requiredNonceProvided().should.equal(true)
    })

    it('should return false when nonce is required and missing', () => {
      let req = { method: 'GET', query: { response_type: 'id_token token' } }
      let request = new AuthenticationRequest(req, {}, { host: {} })
      request.requiredNonceProvided().should.equal(false)
    })
  })

  /**
   * Decode request parameter
   */
  describe('decodeRequestParam', () => {
    let requestJwt

    before(() => {
      sinon.spy(AuthenticationRequest.prototype, 'redirect')
    })

    after(() => {
      AuthenticationRequest.prototype.redirect.restore()
    })

    beforeEach(() => {
      params = {
        client_id: 'https://app.com', response_type: 'code id_token'
      }

      let key = provider.keys.token.signing['RS256'].privateKey

      let requestObject = new JWT({
        key,
        header: { alg: 'RS256' },
        payload: {
          'aud': [ 'https://rs.com ', 'https://app.com' ],
          'azp': 'https://app.com',
          'response_type': 'code id_token',
          'client_id': 'https://app.com',
          'redirect_uri': 'https://app.com/callback',
          'key': {
            "kty": "RSA",
            "alg": "RS256",
            "n": "xykqKb0EPomxUR-W_4oXSqFVwEoD_ZdqSiFfYH-a9r8yGfmugq-fLEuuolQSqrzR3l9U0prBBUeICYBjfuTdRinhMbqkwm8R7_U6dptHe2yILYHLAl0oEooSDKaFMe90h7yDaWiahOewnhh4BWRc_KRNATqx0XGfVmj7Vt4QQifk_xJYZPbLClf8YJ20wKPSebfDzTdh6Jv3sM6ASo5-1PQJNqvk7Dy632E3zIqcQn8wRqQ3hDCJmX3uvMQ3oQNCpJDSvO1kuB0msMWwBwzq3QtUZcDjXovVpi2j3SZfc8X1nlh2H4hge3ATwb1az6IX_OQgn4r1UIsKqIUsTocIrw",
            "e": "AQAB",
            "key_ops": [
              "verify"
            ],
            "ext": true
          }
        }
      }, { filter: false })

      return requestObject.encode()
        .then(jwt => {
          requestJwt = jwt
        })
    })

    it('should pass through the request if no request parameter exists', () => {
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)

      return request.decodeRequestParam(request)
        .then(result => {
          expect(result).to.equal(request)
        })
    })

    it('should throw an error on an invalid request object', done => {
      // invalid_request_object
      params.request = 'invalid jwt'
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)

      request.decodeRequestParam(request)
        .catch(() => {
          expect(request.redirect).to.have.been.calledWith({
            error: 'invalid_request_object',
            error_description: 'Invalid JWT compact serialization'
          })
          done()
        })
    })

    it('should validate the request object', () => {
      params.request = requestJwt
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)

      sinon.spy(request, 'validateRequestParam')

      return request.decodeRequestParam(request)
        .then(() => {
          expect(request.validateRequestParam).to.have.been.called()
        })
    })

    it('should resolve with the argument (request object)', () => {
      params = {
        'response_type': 'code id_token',
        'client_id': 'https://app.com',
        request: requestJwt
      }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)

      return request.decodeRequestParam(request)
        .then(result => {
          expect(result).to.equal(request)
        })
    })

    it('should assign its payload claims to request, superseding its params', () => {
      params = {
        redirect_uri: 'whatever',
        request: requestJwt,
        client_id: 'https://app.com',
        response_type: 'code id_token'
      }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)

      return request.decodeRequestParam(request)
        .then(result => {
          expect(result.params.redirect_uri).to.equal('https://app.com/callback')
          expect(result.params.aud).to.eql([ 'https://rs.com ', 'https://app.com' ])
        })
    })

    it('should load the PoP key', () => {
      params.request = requestJwt
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      let request = new AuthenticationRequest(req, res, provider)

      return request.decodeRequestParam(request)
        .then(result => {
          expect(result.cnfKey.alg).to.equal('RS256')
        })
    })
  })

  describe('validateRequestParam', () => {
    let requestJwt

    beforeEach(() => {
      params = { client_id: 'https://app.com', response_type: 'code id_token' }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      request = new AuthenticationRequest(req, res, provider)
      requestJwt = {
        header: { alg: 'RS256' },
        payload: {}
      }
      sinon.spy(AuthenticationRequest.prototype, 'redirect')
      sinon.spy(AuthenticationRequest.prototype, 'forbidden')
    })

    afterEach(() => {
      AuthenticationRequest.prototype.redirect.restore()
      AuthenticationRequest.prototype.forbidden.restore()
    })

    it('should pass through the request object jwt if no errors', () => {
      return request.validateRequestParam(requestJwt)
        .then(result => {
          expect(result).to.equal(requestJwt)
        })
    })

    it('should throw an error if a request param is present in the jwt', done => {
      requestJwt.payload = { request: {} }

      request.validateRequestParam(requestJwt)
        .catch(err => {
          expect(err).to.exist()
          expect(request.redirect).to.have.been.calledWith({
            error: 'invalid_request_object',
            error_description: 'Illegal request claim in payload'
          })
          done()
        })
    })

    it('should throw an error if a request_uri param is present in the jwt', done => {
      requestJwt.payload = { request_uri: {} }

      request.validateRequestParam(requestJwt)
        .catch(err => {
          expect(err).to.exist()
          expect(request.redirect).to.have.been.calledWith({
            error: 'invalid_request_object',
            error_description: 'Illegal request_uri claim in payload'
          })
          done()
        })
    })

    it('should throw an error on mismatching client_id', done => {
      params = { client_id: 'https://app.com', response_type: 'code id_token' }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      request = new AuthenticationRequest(req, res, provider)

      requestJwt.payload = { client_id: 'something else' }

      request.validateRequestParam(requestJwt)
        .catch(err => {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.calledWith({
            error: 'unauthorized_client',
            error_description: 'Mismatching client id in request object'
          })
          done()
        })
    })

    it('should throw an error on mismatching response_type', done => {
      params = { client_id: 'https://app.com', response_type: 'code id_token' }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      request = new AuthenticationRequest(req, res, provider)

      requestJwt.payload = { response_type: 'token' }

      request.validateRequestParam(requestJwt)
        .catch(err => {
          expect(err).to.exist()
          expect(request.redirect).to.have.been.calledWith({
            error: 'invalid_request',
            error_description: 'Mismatching response type in request object',
          })
          done()
        })
    })

    it('should throw an error on mismatching scope', done => {
      params = { scope: 'openid' }
      req = HttpMocks.createRequest({ method: 'GET', query: params })
      request = new AuthenticationRequest(req, res, provider)

      requestJwt.payload = { scope: 'something else' }

      request.validateRequestParam(requestJwt)
        .catch(err => {
          expect(err).to.exist()
          expect(request.redirect).to.have.been.calledWith({
            error: 'invalid_scope',
            error_description: 'Mismatching scope in request object',
          })
          done()
        })
    })
  })

  /**
   * Validate
   */
  describe('validate', () => {
    let request, provider, client

    describe('with missing client_id parameter', () => {

      before(() => {
        provider = { host: {} }
        sinon.stub(AuthenticationRequest.prototype, 'forbidden')
        params = { 'redirect_uri': 'https://app.com/callback' }
        req = HttpMocks.createRequest({ method: 'GET', query: params })
        request = new AuthenticationRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.forbidden.restore()
      })

      it('should respond "403 Forbidden"', () => {
        request.forbidden.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client id'
        })
      })
    })

    describe('with missing redirect_uri parameter', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'badRequest')
        params = { client_id: 'uuid' }
        req = HttpMocks.createRequest({ method: 'GET', query: params })
        request = new AuthenticationRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing redirect uri'
        })
      })
    })

    describe('with unknown client', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'unauthorized')
        params = { client_id: 'uuid', redirect_uri: 'https://example.com/callback' }
        req = HttpMocks.createRequest({ method: 'GET', query: params })
        provider = { host }
        request = new AuthenticationRequest(req, res, provider)
        request.client = null
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Unknown client'
        })
      })
    })

    describe('with mismatching redirect uri', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'badRequest')
        params = { client_id: 'uuid', redirect_uri: 'https://example.com/wrong' }
        req = HttpMocks.createRequest({ method: 'GET', query: params })
        client = { redirect_uris: ['https://example.com/callback'] }
        provider = { host }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Mismatching redirect uri'
        })
      })
    })

    describe('with missing response_type parameter', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'redirect')
        params = { client_id: 'uuid', redirect_uri: 'https://example.com/callback' }
        req = { method: 'GET', query: params }
        client = {
          redirect_uris: [
            'https://example.com/callback'
          ]
        }
        provider = { host }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.redirect.restore()
      })

      it('should respond "302 Redirect"', () => {
        request.redirect.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing response type'
        })
      })
    })

    describe('with missing scope parameter', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'redirect')
        params = {
          client_id: 'uuid',
          redirect_uri: 'https://example.com/callback',
          response_type: 'code'
        }
        req = { method: 'GET', query: params }
        client = {
          redirect_uris: [
            'https://example.com/callback'
          ]
        }
        provider = { host }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.redirect.restore()
      })

      it('should respond "302 Redirect"', () => {
        request.redirect.should.have.been.calledWith({
          error: 'invalid_scope',
          error_description: 'Missing scope'
        })
      })
    })

    describe('with missing openid scope value', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'redirect')
        params = {
          client_id: 'uuid',
          redirect_uri: 'https://example.com/callback',
          response_type: 'code',
          scope: 'profile'
        }
        req = { method: 'GET', query: params }
        client = {
          redirect_uris: [
            'https://example.com/callback'
          ]
        }
        provider = { host }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.redirect.restore()
      })

      it('should respond "302 Redirect"', () => {
        request.redirect.should.have.been.calledWith({
          error: 'invalid_scope',
          error_description: 'Missing openid scope'
        })
      })
    })

    describe('with missing required nonce', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'redirect')
        params = {
          client_id: 'uuid',
          redirect_uri: 'https://example.com/callback',
          response_type: 'id_token token',
          scope: 'openid profile'
        }
        req = { method: 'GET', query: params }
        client = {
          redirect_uris: [
            'https://example.com/callback'
          ]
        }
        provider = { host }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.redirect.restore()
      })

      it('should respond "302 Redirect"', () => {
        request.redirect.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing nonce'
        })
      })
    })

    describe('with unsupported response type', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'redirect')
        params = {
          client_id: 'uuid',
          redirect_uri: 'https://example.com/callback',
          response_type: 'code unsupported',
          scope: 'openid',
          nonce: 'n0nc3'
        }
        req = { method: 'GET', query: params }
        client = {
          redirect_uris: [
            'https://example.com/callback'
          ]
        }
        provider = {
          host,
          response_types_supported: ['code', 'id_token token']
        }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.redirect.restore()
      })

      it('should respond "302 Redirect"', () => {
        request.redirect.should.have.been.calledWith({
          error: 'unsupported_response_type',
          error_description: 'Unsupported response type'
        })
      })
    })

    describe('with unsupported response mode', () => {
      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'redirect')
        params = {
          client_id: 'uuid',
          redirect_uri: 'https://example.com/callback',
          response_type: 'code',
          response_mode: 'unsupported',
          scope: 'openid',
          nonce: 'n0nc3'
        }
        req = { method: 'GET', query: params }
        client = {
          redirect_uris: [
            'https://example.com/callback'
          ]
        }
        provider = {
          host,
          response_types_supported: ['code', 'id_token token'],
          response_modes_supported: ['query', 'fragment']
        }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
        request.validate(request)
      })

      after(() => {
        AuthenticationRequest.prototype.redirect.restore()
      })

      it('should respond "302 Redirect"', () => {
        request.redirect.should.have.been.calledWith({
          error: 'unsupported_response_mode',
          error_description: 'Unsupported response mode'
        })
      })
    })

    describe('with valid request', () => {
      let promise

      before(() => {
        params = {
          client_id: 'uuid',
          redirect_uri: 'https://example.com/callback',
          response_type: 'code',
          scope: 'openid',
          nonce: 'n0nc3'
        }
        req = { method: 'GET', query: params }
        client = { redirect_uris: 'https://example.com/callback' }
        provider = {
          host,
          response_types_supported: ['code', 'id_token token'],
          response_modes_supported: ['query', 'fragment']
        }
        request = new AuthenticationRequest(req, res, provider)
        request.client = client
      })

      it('should return the request', () => {
        let result = request.validate(request)
        expect(result).to.equal(request)
      })
    })
  })

  describe('authorize', () => {
    let request

    describe('with consent', () => {
      let promise

      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'allow')
        request = new AuthenticationRequest(req, res, provider)
        request.consent = true
        promise = request.authorize(request)
      })

      after(() => {
        AuthenticationRequest.prototype.allow.restore()
      })

      it('should grant access', () => {
        request.allow.should.have.been.called
      })
    })

    describe('without consent', () => {
      let request

      before(() => {
        sinon.stub(AuthenticationRequest.prototype, 'deny')
        req = { method: 'GET', query: { authorize: false } }
        request = new AuthenticationRequest(req, res, provider)
        request.authorize(request)
      })

      after(() => {
        AuthenticationRequest.prototype.deny.restore()
      })

      it('should deny access', () => {
        request.deny.should.have.been.called
      })
    })
  })

  describe('allow', () => {
    let request, client

    before(() => {
      params = {
        client_id: 'uuid',
        redirect_uri: 'https://example.com/callback',
        response_type: 'id_token token',
        scope: 'openid',
        nonce: 'n0nc3'
      }
      req = { method: 'GET', query: params }
      client = {
        redirect_uris: 'https://example.com/callback',
        client_id: 'uuid'
      }

      request = new AuthenticationRequest(req, res, provider)
      request.subject = { '_id': 'user1' }
      request.client = client

      request.redirect = (response) => { return Promise.resolve(response) }
      sinon.spy(request, 'redirect')
    })

    it('should issue an access and id tokens if applicable', () => {
      return request.allow(request)
        .then(response => {
          expect(response.token_type).to.equal('Bearer')
          expect(response.expires_in).to.equal(3600)
          expect(response.id_token).to.exist()
          expect(response.id_token.split('.').length).to.equal(3)
          expect(response.access_token).to.exist()
          expect(response.access_token.split('.').length).to.equal(3)
        })
    })
  })

  describe('deny', () => {
    before(() => {
      sinon.stub(AuthenticationRequest.prototype, 'redirect')
      let request = new AuthenticationRequest({}, {}, { host: {} })
      request.deny(request)
    })

    after(() => {
      AuthenticationRequest.prototype.redirect.restore()
    })

    it('should respond "302 Redirect"', () => {
      AuthenticationRequest.prototype.redirect.should.have.been.calledWith({
        error: 'access_denied'
      })
    })
  })

  describe('includeAccessToken', () => {
    let request, authResponse

    before(() => {
      request = new AuthenticationRequest(req, res, provider)
      authResponse = {}

      sinon.stub(AccessToken, 'issueForRequest')
      AccessToken.issueForRequest.withArgs(request, authResponse).resolves(authResponse)
    })

    after(() => {
      AccessToken.issueForRequest.restore()
    })

    it('should pass through the request if no token is needed', () => {
      request.responseTypes = ['id_token']

      return request.includeAccessToken(authResponse)
        .then(res => {
          expect(res).to.equal(authResponse)
          expect(AccessToken.issueForRequest).to.not.have.been.called()
        })
    })

    it('should issue an access token if response type requires it', () => {
      request.responseTypes = ['token']

      return request.includeAccessToken(authResponse)
        .then(res => {
          expect(res).to.equal(authResponse)
          expect(AccessToken.issueForRequest).to.have.been.called()
        })
    })
  })

  describe('includeAuthorizationCode', () => {
    let request, authResponse, provider

    beforeEach(() => {
      authResponse = {}
      provider = {
        backend: {
          put: sinon.stub().resolves()
        }
      }
      request = new AuthenticationRequest(req, res, provider)
      request.client = { client_id: 'client123' }
      request.subject = { '_id': 'user1' }
      request.responseTypes = ['code']
      request.random = sinon.stub().returns('rand0m')
    })

    it('generates an authorization code and sets it on the response', () => {
      return request.includeAuthorizationCode(authResponse)
        .then(result => {
          expect(result.code).to.equal('rand0m')
        })
    })

    it('stores the corresponding AuthorizationCode instance', () => {
      return request.includeAuthorizationCode(authResponse)
        .then(result => {
          expect(provider.backend.put).to.have.been.calledWith('codes', 'rand0m')
        })
    })
  })

  describe('includeIDToken', () => {
    let req, res, provider, request, authResponse

    before(() => {
      req = { method: 'GET', query: {} }
      res = {}
      provider = { host: {} }
      request = new AuthenticationRequest(req, res, provider)
      authResponse = {}

      sinon.stub(IDToken, 'issueForRequest')
      IDToken.issueForRequest.withArgs(request, authResponse).resolves(authResponse)
    })

    after(() => {
      IDToken.issueForRequest.restore()
    })

    it('should pass through the request if no id token is needed', () => {
      request.responseTypes = ['token']

      return request.includeIDToken(authResponse)
        .then(res => {
          expect(res).to.equal(authResponse)
          expect(IDToken.issueForRequest).to.not.have.been.called()
        })
    })

    it('should issue an id token if response type requires it', () => {
      request.responseTypes = ['id_token']

      return request.includeIDToken(authResponse)
        .then(res => {
          expect(res).to.equal(authResponse)
          expect(IDToken.issueForRequest).to.have.been.called()
        })
    })
  })

  describe('includeSessionState', () => {
    it('should exist', () => {
      let req = { method: 'GET', query: {} }
      let res = {}
      let provider = { host: {} }
      let request = new AuthenticationRequest(req, res, provider)

      expect(() => request.includeSessionState(request))
        .to.not.throw()
    })
  })
})
