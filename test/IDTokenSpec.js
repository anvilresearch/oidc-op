'use strict'

/**
 * Test dependencies
 */
const chai = require('chai')
const fs = require('fs')
const path = require('path')
const { JWT } = require('@trust/jose')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.use(require('chai-as-promised'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const Provider = require('../src/Provider')
const IDToken = require('../src/IDToken')
const IDTokenSchema = require('../src/schemas/IDTokenSchema')

/**
 * Tests
 */
describe('IDToken', () => {
  const providerUri = 'https://example.com'
  var provider

  before(function () {
    this.timeout(5000)

    let configPath = path.join(__dirname, 'config', 'provider.json')

    let storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))

    provider = new Provider(storedConfig)

    return provider.initializeKeyChain(provider.keys)
  })

  /**
   * Schema
   */
  describe('schema', () => {
    it('should reference the AccessToken Schema', () => {
      IDToken.schema.should.equal(IDTokenSchema)
    })
  })

  describe('issue()', () => {
    let code
    let subject = { _id: 'user123' }
    let client = { 'client_id': 'client123' }
    let request, response
    let params = {}

    beforeEach(() => {
      request = { params, code, provider, client, subject }
      response = {}
    })

    it('should issue an id token', () => {
      return IDToken.issue(request, response)
        .then(res => {
          return JWT.decode(res['id_token'])
        })
        .then(token => {
          expect(token.type).to.equal('JWS')
          expect(token.header.alg).to.equal('RS256')
          expect(token.payload.iss).to.equal(providerUri)
          expect(token.payload.sub).to.equal('user123')
        })
    })
  })
})
