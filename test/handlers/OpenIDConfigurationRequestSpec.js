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
const OpenIDConfigurationRequest = require('../../src/handlers/OpenIDConfigurationRequest')

/**
 * Tests
 */
describe('OpenIDConfigurationRequest', () => {
  const providerUri = 'https://example.com'
  let req, res, provider

  beforeEach(() => {
    req = HttpMocks.createRequest()
    res = HttpMocks.createResponse()

    provider = new Provider({ issuer: providerUri })
  })

  it('should respond with the provider configuration in JSON format', () => {
    OpenIDConfigurationRequest.handle(req, res, provider)

    expect(res._isJSON()).to.be.true()

    let config = JSON.parse(res._getData())

    expect(config['authorization_endpoint']).to.equal('https://example.com/authorize')
  })
})
