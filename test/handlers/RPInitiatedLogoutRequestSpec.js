'use strict'

const chai = require('chai')
const expect = chai.expect
const sinon = require('sinon')
const sinonChai = require('sinon-chai')
chai.use(require('dirty-chai'))
chai.use(sinonChai)
chai.should()
const HttpMocks = require('node-mocks-http')

const RPInitiatedLogoutRequest = require('../../src/handlers/RPInitiatedLogoutRequest')

const provider = {
  host: {
    logout: () => {}
  }
}

const postLogoutRedirectUri = 'https://rp.example.com/goodbye'
const reqNoParams = HttpMocks.createRequest({ method: 'GET', params: {} })
const reqWithParams = HttpMocks.createRequest({
  method: 'GET',
  query: {
    'id_token_hint': {},
    'state': 'abc123',
    'post_logout_redirect_uri': postLogoutRedirectUri
  }
})

describe('RPInitiatedLogoutRequest', () => {
  describe('handle()', () => {
    it('should invoke injected host.logout', done => {
      let res = HttpMocks.createResponse()
      let logoutSpy = sinon.stub(provider.host, 'logout').resolves()

      RPInitiatedLogoutRequest.handle(reqNoParams, res, provider)
        .then(() => {
          expect(logoutSpy).to.have.been.called()
          done()
        })
    })
  })

  describe('constructor()', () => {
    it('should parse the incoming request params', done => {
      let res = {}
      let request = new RPInitiatedLogoutRequest(reqWithParams, res, provider)

      expect(request).to.have.property('params')
      expect(Object.keys(request.params).length).to.equal(3)
      expect(request.params.state).to.equal('abc123')
      done()
    })
  })

  describe('validate()', () => {
    it('should validate the `id_token_hint` param')
    it('should validate that `post_logout_redirect_uri` has been registered')
  })

  describe('redirectOrRespond()', () => {
    it('should redirect to RP if logout uri provided', done => {
      let res = HttpMocks.createResponse()
      let req = HttpMocks.createRequest({
        method: 'GET',
        query: {
          'post_logout_redirect_uri': postLogoutRedirectUri
        }
      })
      let request = new RPInitiatedLogoutRequest(req, res, provider)
      request.respond = sinon.stub().throws()

      request.redirectOrRespond()

      expect(request.respond).to.not.have.been.called()
      expect(res.statusCode).to.equal(302)
      expect(res._getRedirectUrl()).to.equal(postLogoutRedirectUri)
      done()
    })

    it('should respond with a 204 if no logout uri provided', done => {
      let res = HttpMocks.createResponse()
      let request = new RPInitiatedLogoutRequest(reqNoParams, res, provider)
      request.redirectToRP = sinon.stub().throws()

      request.redirectOrRespond()

      expect(request.redirectToRP).to.not.have.been.called()
      expect(res.statusCode).to.equal(204)
      done()
    })
  })

  describe('redirectToRP()', () => {
    it('should redirect to provided URI')
    it('should pass through the state param')
  })
})
