'use strict'

/**
 * Test dependencies
 */
const fs = require('fs')
const path = require('path')
const chai = require('chai')
const HttpMocks = require('node-mocks-http')

/**
 * Assertions
 */
const sinon = require('sinon')
chai.use(require('dirty-chai'))
chai.use(require('sinon-chai'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const Provider = require('../../src/Provider')
const Client = require('../../src/Client')
const DynamicRegistrationRequest = require('../../src/handlers/DynamicRegistrationRequest')
const MemoryStore = require('../backends/MemoryStore')

/**
 * Tests
 */
describe('DynamicRegistrationRequest', () => {
  const providerUri = 'https://example.com'
  let req, res, provider
  let request

  before(function () {
    this.timeout(5000)

    let configPath = path.join(__dirname, '..', 'config', 'provider.json')

    let storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))

    provider = new Provider(storedConfig)

    provider.inject({ backend: new MemoryStore() })

    return provider.initializeKeyChain(provider.keys)
  })

  beforeEach(() => {
    req = HttpMocks.createRequest({
      body: {
        client_id: 'https://app.example.com',
        redirect_uris: [ 'https://app.example.com/callback' ]
      }
    })
    res = HttpMocks.createResponse()

    provider.backend.data = {}

    request = new DynamicRegistrationRequest(req, res, provider)
    sinon.spy(request, 'badRequest')
  })

  describe('validate', () => {
    it('should throw an error on missing registration', done => {
      request.req.body = undefined

      try {
        request.validate(request)
      } catch (err) {
        expect(err.error_description).to.equal('Missing registration request body')
        expect(request.badRequest).to.have.been.called()
        done()
      }
    })

    it('should throw an error on missing redirect_uris', done => {
      request.req.body.redirect_uris = undefined

      try {
        request.validate(request)
      } catch (err) {
        expect(err.error_description).to.equal('Missing redirect_uris parameter')
        expect(request.badRequest).to.have.been.called()
        done()
      }
    })

    it('should throw a validation error when client does not pass validation', done => {
      request.req.body.application_type = 123  // app type must be a string

      try {
        request.validate(request)
      } catch (err) {
        expect(err.error_description).to.match(/Client validation error/)
        expect(request.badRequest).to.have.been.called()
        done()
      }
    })

    it('should generate a client_id if one is not provided', () => {
      request.req.body.client_id = undefined
      request.req.body.response_types = ['id_token token']
      sinon.spy(request, 'identifier')

      request.validate(request)

      expect(request.identifier).to.have.been.called()
      expect(request.client.client_id).to.exist()
    })

    it('should generate a client_secret for non-implicit requests', () => {
      request.req.body.response_types = ['code']

      sinon.spy(request, 'secret')

      request.validate(request)

      expect(request.secret).to.have.been.called()
      expect(request.client.client_secret).to.exist()
    })

    it('should return the request object', () => {
      let result = request.validate(request)

      expect(result).to.equal(result)
    })

    it('should set a registered client on the request object', () => {
      let result = request.validate(request)

      expect(result.client).to.be.an.instanceof(Client)
    })
  })

  describe('register', () => {
    it('should store a registered client in the clients collection', () => {
      let client = { client_id: 'client123' }

      request.client = client

      return request.register(request)
        .then(() => {
          return provider.backend.get('clients', 'client123')
        })
        .then(storedClient => {
          expect(storedClient).to.eql(client)
        })
    })
  })

  describe('token', () => {
    it('should create an access token', () => {
      return Promise.resolve(request)
        .then(request => request.validate(request))
        .then(request => request.token(request))
        .then(result => {
          expect(result).to.equal(request)
          let token = result.compact
          expect(token.split('.').length).to.equal(3)  // is a JWT
        })
    })
  })

  describe('respond', () => {
    beforeEach(() => {
      request.client = {
        client_id: 'https://app.example.com'
      }
      request.compact = 't0ken'
    })

    it('responds with a 201 status code', () => {
      request.respond(request)

      expect(res._getStatusCode()).to.equal(201)
    })

    it('sets cache control response headers', () => {
      request.respond(request)

      let headers = res._getHeaders()

      expect(headers['Cache-Control']).to.equal('no-store')
      expect(headers['Pragma']).to.equal('no-cache')
    })

    it('responds with a client registration object', () => {
      request.respond(request)

      let registration = JSON.parse(res._getData())

      expect(registration.registration_access_token).to.equal('t0ken')
      expect(registration.registration_client_uri)
        .to.equal('https://example.com/register/https%3A%2F%2Fapp.example.com')
      expect(registration).to.have.property('client_id_issued_at')
    })

    it('sets the client_secret_expires_at property if applicable', () => {
      request.client.client_secret = 's33cret'

      request.respond(request)

      let registration = JSON.parse(res._getData())

      expect(registration.client_secret_expires_at).to.equal(0)
    })
  })

  describe('static handle', () => {
    it('performs dynamic registration', () => {
      return DynamicRegistrationRequest.handle(req, res, provider)
        .then(response => {
          expect(res._getStatusCode()).to.equal(201)
          let registration = JSON.parse(res._getData())

          expect(registration.registration_access_token).to.exist()
          expect(registration.response_types).to.eql(['code'])
        })
    })
  })
})
