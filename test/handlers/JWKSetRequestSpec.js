'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const HttpMocks = require('node-mocks-http')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const Provider = require('../../src/Provider')
const JWKSetRequest = require('../../src/handlers/JWKSetRequest')

/**
 * Tests
 */
describe('JWKSetRequest', () => {
  const providerUri = 'https://example.com'
  let req, res, provider

  before(function () {
    this.timeout(5000)

    req = HttpMocks.createRequest()
    res = HttpMocks.createResponse()

    provider = new Provider({ issuer: providerUri })

    return provider.initializeKeyChain()
  })

  it('should respond with the provider configuration in JSON format', () => {
    JWKSetRequest.handle(req, res, provider)

    expect(res._isJSON()).to.be.true()

    let jwks = JSON.parse(res._getData())

    expect(jwks.keys).to.exist()
    expect(jwks.keys[0].alg).to.equal('RS256')
  })
})
