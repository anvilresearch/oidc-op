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
const AccessToken = require('../src/AccessToken')
const AccessTokenSchema = require('../src/schemas/AccessTokenSchema')
const MemoryStore = require('./backends/MemoryStore')

/**
 * Tests
 */
describe('AccessToken', () => {
  const providerUri = 'https://example.com'
  var provider

  before(function () {
    this.timeout(5000)

    let configPath = path.join(__dirname, 'config', 'provider.json')

    let storedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'))

    provider = new Provider(storedConfig)

    provider.inject({ backend: new MemoryStore() })

    return provider.initializeKeyChain(provider.keys)
  })

  /**
   * Schema
   */
  describe('schema', () => {
    it('should reference the AccessToken Schema', () => {
      AccessToken.schema.should.equal(AccessTokenSchema)
    })
  })

  describe('random', () => {
    it('should return a random string', () => {
      let result = AccessToken.random(8)  // 8 bytes / 16 chars

      expect(typeof result).to.equal('string')
      expect(result.length).to.equal(16)
    })
  })

  describe('issueForRequest()', () => {
    let subject = { _id: 'user123' }
    let client = { 'client_id': 'client123' }
    let request, response
    let params = {}
    let scope = ['token']

    describe('authentication requests', () => {
      let code

      beforeEach(() => {
        request = { params, code, provider, client, subject, scope }
        response = {}
      })

      it('should issue an access token', () => {
        return AccessToken.issueForRequest(request, response)
          .then(res => {
            expect(res['token_type']).to.equal('Bearer')
            expect(res['expires_in']).to.equal(3600)

            return JWT.decode(res['access_token'])
          })
          .then(token => {
            expect(token.type).to.equal('JWS')
            expect(token.header.alg).to.equal('RS256')
            expect(token.payload.iss).to.equal(providerUri)
            expect(token.payload.sub).to.equal('user123')
            expect(token.payload.jti).to.exist()
            expect(token.payload.scope).to.eql(['token'])
          })
      })
    })

    describe('auth code request', () => {
      let code

      beforeEach(() => {
        code = {
          aud: 'client123',
          sub: 'user123',
          scope: ['token']
        }

        request = { params, code, provider, client, subject }
        response = {}
      })

      it('should issue an access token', () => {
        return AccessToken.issueForRequest(request, response)
          .then(res => {
            expect(res['token_type']).to.equal('Bearer')
            expect(res['expires_in']).to.equal(3600)

            return JWT.decode(res['access_token'])
          })
          .then(token => {
            expect(token.type).to.equal('JWS')
            expect(token.header.alg).to.equal('RS256')
            expect(token.payload.iss).to.equal(providerUri)
            expect(token.payload.sub).to.equal('user123')
            expect(token.payload.scope).to.eql(['token'])
          })
      })
    })
  })

  describe('issue()', () => {
    let options

    beforeEach(() => {
      options = {
        aud: 'client123',
        sub: 'user123',
        scope: 'openid profile'
      }
    })

    it('should issue an access token', () => {
      let token = AccessToken.issue(provider, options)

      expect(token.payload.iss).to.equal(provider.issuer)
      expect(token.payload.aud).to.equal('client123')
      expect(token.payload.sub).to.equal('user123')
      expect(token.payload.scope).to.equal('openid profile')
    })

    it('should issue an access token with passed in values', () => {
      options.alg = 'RS512'

      let randomId = AccessToken.random(8)
      options.jti = randomId

      let now = Math.floor(Date.now() / 1000)
      options.iat = now

      options.max = 3000

      let token = AccessToken.issue(provider, options)

      expect(token.payload.jti).to.equal(randomId)
      expect(token.payload.iat).to.equal(now)
      expect(token.payload.exp - token.payload.iat).to.equal(3000)

      expect(token.header.alg).to.equal('RS512')
    })

    it('should init with defaults', () => {
      let token = AccessToken.issue(provider, options)

      expect(token.header.alg).to.equal(AccessToken.DEFAULT_SIG_ALGORITHM)
      expect(token.header.kid).to.exist()

      expect(token.payload.jti).to.exist()
      expect(token.payload.exp).to.exist()
      expect(token.payload.iat).to.exist()

      expect(token.payload.exp - token.payload.iat)
        .to.equal(AccessToken.DEFAULT_MAX_AGE)

      expect(token.key).to.exist()
    })
  })
})
