'use strict'

/**
 * Test dependencies
 */
const cwd = process.cwd()
const path = require('path')
const chai = require('chai')
const sinon = require('sinon')
const HttpMocks = require('node-mocks-http')

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
const TokenRequest = require(path.join(cwd, 'src', 'handlers', 'TokenRequest'))
const AccessToken = require(path.join(cwd, 'src', 'AccessToken'))
const IDToken = require(path.join(cwd, 'src', 'IDToken'))

/**
 * Tests
 */
describe('TokenRequest', () => {

  /**
   * Handle
   */
  describe('handle', () => {})

  /**
   * Constructor
   */
  describe('constructor', () => {
    let params, request

    before(() => {
      params = { grant_type: 'authorization_code' }
      let req = { method: 'POST', body: params }
      let res = {}
      let provider = { host: {} }
      request = new TokenRequest(req, res, provider)
    })

    it('should set "params" from request body', () => {
      request.params.should.equal(params)
    })

    it('should set "grantType" from params', () => {
      request.grantType.should.equal(params.grant_type)
    })
  })

  /**
   * Get Grant Type
   */
  describe('getGrantType', () => {
    it('should return the "grant_type" parameter', () => {
      TokenRequest.getGrantType({
        params: {
          grant_type: 'authorization_code'
        }
      }).should.equal('authorization_code')
    })
  })

  /**
   * Supported Grant Type
   */
  describe('supportedGrantType', () => {
    let res, host, provider

    beforeEach(() => {
      res = {}
      host = {}
      provider = { host, grant_types_supported: ['authorization_code'] }
    })

    it('should return true with a supported response type parameter', () => {
      let params = { grant_type: 'authorization_code' }
      let req = { method: 'POST', body: params }
      let request = new TokenRequest(req, res, provider)
      request.supportedGrantType().should.equal(true)
    })

    it('should return false with an unsupported response type parameter', () => {
      let params = { grant_type: 'other' }
      let req = { method: 'POST', body: params }
      let request = new TokenRequest(req, res, provider)
      request.supportedGrantType().should.equal(false)
    })
  })

  /**
   * Validate
   */
  describe('validate', () => {
    describe('with missing grant_type parameter', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = {}
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host }
        request = new TokenRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing grant type'
        })
      })
    })

    describe('with unsupported grant type', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'unsupported' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['authorization_code'] }
        request = new TokenRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unsupported_grant_type',
          error_description: 'Unsupported grant type'
        })
      })
    })

    describe('with missing authorization code', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'authorization_code' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['authorization_code'] }
        request = new TokenRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing authorization code'
        })
      })
    })

    describe('with missing redirect uri', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'authorization_code', code: 'c0d3' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['authorization_code'] }
        request = new TokenRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing redirect uri'
        })
      })
    })

    describe('with missing refresh token parameter', () => {
      let params, req, res, host, provider, request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')
        params = { grant_type: 'refresh_token' }
        req = { method: 'POST', body: params }
        res = {}
        host = {}
        provider = { host, grant_types_supported: ['refresh_token'] }
        request = new TokenRequest(req, res, provider)
        request.validate(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 bad request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'invalid_request',
          error_description: 'Missing refresh token'
        })
      })
    })
  })

  /**
   * Authenticate Client
   */
  describe('authenticateClient', () => {
    describe('with "client_secret_basic" and "client_secret_post" credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let params = {
          grant_type: 'client_credentials',
          client_secret: 's3cr3t'
        }
        let req = {
          method: 'POST',
          body: params,
          headers: {
            authorization: 'Basic base64str'
          }
        }
        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      })
    })

    describe('with "client_secret_basic" and "client_secret_jwt" credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let params = {
          grant_type: 'client_credentials',
          client_assertion_type: 'type'
        }

        let req = {
          method: 'POST',
          body: params,
          headers: {
            authorization: 'Basic base64str'
          }
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      })
    })

    describe('with "client_secret_post" and "client_secret_jwt" credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let params = {
          grant_type: 'client_credentials',
          client_secret: 's3cr3t',
          client_assertion_type: 'type'
        }

        let req = {
          method: 'POST',
          body: params
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Must use only one authentication method'
        })
      })
    })

    describe('with invalid client assertion type', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let params = {
          grant_type: 'client_credentials',
          client_assertion_type: 'type'
        }

        let req = {
          method: 'POST',
          body: params
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Invalid client assertion type'
        })
      })

    })

    describe('with missing client assertion', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let params = {
          grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        }

        let req = {
          method: 'POST',
          body: params
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client assertion'
        })
      })
    })

    describe('with missing client credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let params = {
          grant_type: 'client_credentials'
        }

        let req = {
          method: 'POST',
          body: params
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with well formed "client_secret_basic" credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'clientSecretBasic')

        let params = {
          grant_type: 'client_credentials'
        }

        let req = {
          method: 'POST',
          body: params,
          headers: {
            authorization: 'Basic base64str'
          }
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.clientSecretBasic.restore()
      })

      it('should invoke "client_secret_basic" authentication', () => {
        request.clientSecretBasic.should.have.been.calledWith(request)
      })
    })

    describe('with well formed "client_secret_post" credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'clientSecretPost')

        let params = {
          grant_type: 'client_credentials',
          client_id: 'uuid',
          client_secret: 's3cr3t'
        }

        let req = {
          method: 'POST',
          body: params
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.clientSecretPost.restore()
      })

      it('should invoke "client_secret_post" authentication', () => {
        request.clientSecretPost.should.have.been.calledWith(request)
      })
    })

    describe('with well formed "client_secret_jwt" credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'clientSecretJWT')

        let params = {
          grant_type: 'client_credentials',
          client_assertion: 'jwt',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        }

        let req = {
          method: 'POST',
          body: params
        }

        let res = {}
        let host = {}
        let provider = { host, grant_types_supported: ['client_credentials'] }

        request = new TokenRequest(req, res, provider)
        request.authenticateClient(request)
      })

      after(() => {
        TokenRequest.prototype.clientSecretJWT.restore()
      })

      it('should invoke "client_secret_jwt" authentication', () => {
        request.clientSecretJWT.should.have.been.calledWith(request)
      })
    })
  })

  /**
   * Client Secret Basic
   */
  describe('clientSecretBasic', () => {
    describe('with malformed credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: 'Basic MALFORMED'
          }
        }

        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.clientSecretBasic(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Malformed HTTP Basic credentials'
        })
      })
    })

    describe('with invalid authorization scheme', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Bearer ${new Buffer('id:secret').toString('base64')}`
          }
        }

        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.clientSecretBasic(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Invalid authorization scheme'
        })
      })
    })

    describe('with missing credentials', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${new Buffer(':').toString('base64')}`
          }
        }

        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.clientSecretBasic(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with unknown client', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        let req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${new Buffer('id:secret').toString('base64')}`
          }
        }

        let res = {}
        let provider = {
          host: {},
          backend: { get: () => Promise.resolve(null) }
        }

        request = new TokenRequest(req, res, provider)
        request.clientSecretBasic(request)
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Unknown client identifier'
        })
      })
    })

    describe('with mismatching secret', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        let req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${new Buffer('id:WRONG').toString('base64')}`
          }
        }

        let res = {}
        let provider = {
          host: {},
          backend: { get: () => Promise.resolve({ client_secret: 'secret' }) }
        }

        request = new TokenRequest(req, res, provider)
        request.clientSecretBasic(request)
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Mismatching client secret'
        })
      })
    })

    describe('with valid credentials', () => {
      let request, promise

      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        let req = {
          method: 'POST',
          body: {},
          headers: {
            authorization: `Basic ${new Buffer('id:secret').toString('base64')}`
          }
        }

        let res = {}
        let provider = {
          host: {},
          backend: { get: () => Promise.resolve({ client_secret: 'secret' }) }
        }

        request = new TokenRequest(req, res, provider)
        promise = request.clientSecretBasic(request)
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve request', () => {
        promise.then(result => result.should.equal(request))
      })
    })
  })

  /**
   * Client Secret Post
   */
  describe('clientSecretPost', () => {
    describe('with missing client id', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let req = {
          method: 'POST',
          body: {
            client_secret: 'secret'
          }
        }

        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.clientSecretPost(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with missing client secret', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'badRequest')

        let req = {
          method: 'POST',
          body: {
            client_id: 'secret'
          }
        }

        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.clientSecretPost(request)
      })

      after(() => {
        TokenRequest.prototype.badRequest.restore()
      })

      it('should respond "400 Bad Request"', () => {
        request.badRequest.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Missing client credentials'
        })
      })
    })

    describe('with unknown client', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        let req = {
          method: 'POST',
          body: {
            client_id: 'uuid',
            client_secret: 'secret'
          }
        }

        let res = {}
        let provider = {
          host: {},
          backend: { get: () => Promise.resolve(null) }
        }

        request = new TokenRequest(req, res, provider)
        request.clientSecretPost(request)
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Unknown client identifier'
        })
      })
    })

    describe('with mismatching client secret', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        let req = {
          method: 'POST',
          body: {
            client_id: 'uuid',
            client_secret: 'WRONG'
          }
        }

        let res = {}
        let provider = {
          host: {},
          backend: { get: () => Promise.resolve({ client_secret: 'secret' }) }
        }

        request = new TokenRequest(req, res, provider)
        request.clientSecretPost(request)
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should respond "401 Unauthorized"', () => {
        request.unauthorized.should.have.been.calledWith({
          error: 'unauthorized_client',
          error_description: 'Mismatching client secret'
        })
      })
    })

    describe('with valid credentials', () => {
      let request, promise

      before(() => {
        sinon.stub(TokenRequest.prototype, 'unauthorized')

        let req = {
          method: 'POST',
          body: {
            client_id: 'uuid',
            client_secret: 'secret'
          }
        }

        let res = {}
        let provider = {
          host: {},
          backend: { get: () => Promise.resolve({ client_secret: 'secret' }) }
        }

        request = new TokenRequest(req, res, provider)
        promise = request.clientSecretPost(request)
      })

      after(() => {
        TokenRequest.prototype.unauthorized.restore()
      })

      it('should return a promise', () => {
        promise.should.be.instanceof(Promise)
      })

      it('should resolve request', () => {
        promise.then(result => result.should.equal(request))
      })
    })
  })

  /**
   * Client Secret JWT
   */
  describe('clientSecretJWT', () => {})

  /**
   * Private Key JWT
   */
  describe('privateKeyJWT', () => {})

  /**
   * None
   */
  describe('none', () => {})

  /**
   * Grant
   */
  describe('grant', () => {
    describe('with "authorization_code" grant type', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'authorizationCodeGrant')

        let req = { method: 'POST', body: { grant_type: 'authorization_code' } }
        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.grant(request)
      })

      after(() => {
        TokenRequest.prototype.authorizationCodeGrant.restore()
      })

      it('should invoke authorizationCodeGrant', () => {
        request.authorizationCodeGrant.should.have.been.calledWith(request)
      })
    })

    describe('with "refresh_token" grant type', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'refreshTokenGrant')

        let req = { method: 'POST', body: { grant_type: 'refresh_token' } }
        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.grant(request)
      })

      after(() => {
        TokenRequest.prototype.refreshTokenGrant.restore()
      })

      it('should invoke refreshTokenGrant', () => {
        request.refreshTokenGrant.should.have.been.calledWith(request)
      })
    })

    describe('with "client_credentials" grant type', () => {
      let request

      before(() => {
        sinon.stub(TokenRequest.prototype, 'clientCredentialsGrant')

        let req = { method: 'POST', body: { grant_type: 'client_credentials' } }
        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
        request.grant(request)
      })

      after(() => {
        TokenRequest.prototype.clientCredentialsGrant.restore()
      })

      it('should invoke clientCredentialsGrant', () => {
        request.clientCredentialsGrant.should.have.been.calledWith(request)
      })
    })

    describe('with unknown grant type', () => {
      let request

      before(() => {
        let req = { method: 'POST', body: { grant_type: 'noyoudint' } }
        let res = {}
        let provider = { host: {} }

        request = new TokenRequest(req, res, provider)
      })

      it('should throw and error', () => {
        expect(() => {
          request.grant(request)
        }).to.throw('Unsupported response type')
      })
    })
  })

  /**
   * Authorization Code Grant
   */
  describe('authorizationCodeGrant', () => {
    let params, request, tokenResponse

    beforeEach(() => {
      tokenResponse = {}
      params = { grant_type: 'authorization_code' }
      let req = { method: 'POST', body: params }
      let res = {
        json: sinon.stub()
      }
      let provider = { host: {} }
      request = new TokenRequest(req, res, provider)

      request.includeAccessToken = sinon.stub().resolves(tokenResponse)
      request.includeIDToken = sinon.stub().resolves(tokenResponse)
    })

    it('should issue an access token', () => {
      return request.authorizationCodeGrant(request)
        .then(() => {
          expect(request.includeAccessToken).to.have.been.called()
        })
    })

    it('should issue an id token', () => {
      return request.authorizationCodeGrant(request)
        .then(() => {
          expect(request.includeIDToken).to.have.been.calledWith(tokenResponse)
        })
    })

    it('should send a response in json format', () => {
      return request.authorizationCodeGrant(request)
        .then(() => {
          expect(request.res.json).to.have.been.calledWith(tokenResponse)
        })
    })
  })

  /**
   * Refresh Token Grant
   */
  describe('refreshTokenGrant', () => {})

  /**
   * Client Credentials Grant
   */
  describe('clientCredentialsGrant', () => {
    let params, request
    const accessToken = 'accesst0ken'

    before(() => {
      sinon.stub(AccessToken, 'issueForRequest')
      AccessToken.issueForRequest.resolves(accessToken)
    })

    after(() => {
      AccessToken.issueForRequest.restore()
    })

    beforeEach(() => {
      params = { grant_type: 'authorization_code' }
      let req = { method: 'POST', body: params }
      let res = {
        json: sinon.stub(),
        set: sinon.stub()
      }
      let provider = { host: {} }
      request = new TokenRequest(req, res, provider)
      request.client = {}
    })

    it('should set the cache control response headers', () => {
      return request.clientCredentialsGrant(request)
        .then(() => {
          expect(request.res.set).to.have.been.calledWith({
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache'
          })
        })
    })

    it('should send the json response', () => {
      request.client.default_max_age = 3000

      return request.clientCredentialsGrant(request)
        .then(() => {
          expect(request.res.json).to.have.been.calledWith({
            access_token: "accesst0ken", expires_in: 3000, token_type: "Bearer"
          })
        })
    })

    it('should only set the expires_in property if applicable', () => {
      request.client.default_max_age = undefined

      return request.clientCredentialsGrant(request)
        .then(() => {
          expect(request.res.json).to.have.been.calledWith({
            access_token: "accesst0ken", token_type: "Bearer"
          })
        })
    })
  })

  /**
   * Verify Authorization Code
   */
  describe('verifyAuthorizationCode', () => {
    const code = 'c0de123'
    let request, provider, res, authCode

    beforeEach(() => {
      let req = {
        method: 'POST',
        body: {
          code,
          client_id: 'uuid',
          client_secret: 'secret',
          grant_type: 'authorization_code',
          redirect_uri: 'https://app.com/callback'
        }
      }

      res = HttpMocks.createResponse()
      provider = {
        host: {},
        backend: {
          get: sinon.stub()
        }
      }

      authCode = {
        exp: Math.floor(Date.now() / 1000) + 1000,
        redirect_uri: 'https://app.com/callback',
        aud: 'client123'
      }

      provider.backend.get.withArgs('codes', code).resolves(authCode)

      request = new TokenRequest(req, res, provider)

      request.client = {
        client_id: 'client123'
      }

      sinon.spy(request, 'badRequest')
    })

    it('should pass through the request if grant type is not authorization_code', () => {
      request.grantType = 'something'

      return request.verifyAuthorizationCode(request)
        .then(result => {
          expect(result).to.equal(request)
        })
    })

    it('should throw an error when no saved authorization code is found', done => {
      provider.backend.get = sinon.stub().resolves(null)

      request.verifyAuthorizationCode(request)
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Authorization not found')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error when the auth code was previously used', done => {
      authCode.used = true

      request.verifyAuthorizationCode(request)
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Authorization code invalid')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error when the auth code is expired', done => {
      authCode.exp = Math.floor(Date.now() / 1000) - 1000

      request.verifyAuthorizationCode(request)
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Authorization code expired')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error on redirect_uri mismatch', done => {
      authCode.redirect_uri = 'something'

      request.verifyAuthorizationCode(request)
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Mismatching redirect uri')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should throw an error on mismatching client id', done => {
      authCode.aud = 'someOtherClient'

      request.verifyAuthorizationCode(request)
        .catch(err => {
          expect(err.error).to.equal('invalid_grant')
          expect(err.error_description).to.equal('Mismatching client id')
          expect(request.badRequest).to.have.been.called()
          done()
        })
    })

    it('should set the request code when successful', () => {
      return request.verifyAuthorizationCode(request)
        .then(result => {
          expect(result).to.equal(request)
          expect(request.code).to.equal(authCode)
        })
    })
  })

  /**
   * Include Access Token
   */
  describe('includeAccessToken', () => {
    let params, request, tokenResponse

    beforeEach(() => {
      tokenResponse = {}
      params = { grant_type: 'authorization_code' }
      let req = { method: 'POST', body: params }
      let res = {}
      let provider = { host: {} }
      request = new TokenRequest(req, res, provider)

      sinon.stub(AccessToken, 'issueForRequest')
      AccessToken.issueForRequest.resolves()
    })

    after(() => {
      AccessToken.issueForRequest.restore()
    })

    it('should issue an access token', () => {
      return request.includeAccessToken(tokenResponse)
        .then(() => {
          expect(AccessToken.issueForRequest).to.have.been
            .calledWith(request, tokenResponse)
        })
    })
  })

  /**
   * Include Refresh Token
   */
  describe('includeRefreshToken', () => {})

  /**
   * Include ID Token
   */
  describe('includeIDToken', () => {
    let params, request, tokenResponse

    before(() => {
      tokenResponse = {}
      params = { grant_type: 'authorization_code' }
      let req = { method: 'POST', body: params }
      let res = {}
      let provider = { host: {} }
      request = new TokenRequest(req, res, provider)

      sinon.stub(IDToken, 'issue')
      IDToken.issue.resolves()
    })

    after(() => {
      IDToken.issue.restore()
    })

    it('should issue an id token', () => {
      return request.includeIDToken(tokenResponse)
        .then(() => {
          expect(IDToken.issue).to.have.been
            .calledWith(request, tokenResponse)
        })
    })
  })

  /**
   * Include Session State
   * TODO: should this be on the base class?
   */
  describe('includeSessionState', () => {})
})
