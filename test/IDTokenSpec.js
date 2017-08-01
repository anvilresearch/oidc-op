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
    it('should reference the IDToken Schema', () => {
      IDToken.schema.should.equal(IDTokenSchema)
    })
  })

  describe('issueForRequest()', () => {
    let code
    let subject = { _id: 'user123' }
    let client
    let request, response
    let params, cnfKey

    describe('authentication request', () => {
      beforeEach(() => {
        client = { 'client_id': 'client123' }
        params = { nonce: 'nonce123' }
        cnfKey = {}
        request = { params, code, provider, client, subject, cnfKey }
        response = {}
      })

      it('should issue an id token', () => {
        return IDToken.issueForRequest(request, response)
          .then(res => {
            return JWT.decode(res['id_token'])
          })
          .then(token => {
            expect(token.type).to.equal('JWS')
            expect(token.header.alg).to.equal('RS256')
            expect(token.payload.iss).to.equal(providerUri)
            expect(token.payload.sub).to.equal('user123')
            expect(token.payload.aud).to.equal('client123')
            expect(token.payload.azp).to.equal('client123')
            expect(token.payload.cnf).to.eql({ jwk: cnfKey })
          })
      })
    })

    describe('auth code / token request', () => {
      beforeEach(() => {
        params = {}
        code = {
          aud: 'client123',
          sub: 'user123',
          nonce: 'nonce123'
        }
        cnfKey = {}
        request = { params, code, provider, client, subject, cnfKey }
        response = {
          code: 'c0de',
          access_token: 't0ken'
        }
      })

      it('should issue an id token', () => {
        return IDToken.issueForRequest(request, response)
          .then(res => {
            return JWT.decode(res['id_token'])
          })
          .then(token => {
            expect(token.type).to.equal('JWS')
            expect(token.header.alg).to.equal('RS256')
            expect(token.payload.iss).to.equal(providerUri)
            expect(token.payload.sub).to.equal('user123')
            expect(token.payload.aud).to.equal('client123')
            expect(token.payload.azp).to.equal('client123')
            expect(token.payload.nonce).to.equal('nonce123')
            expect(token.payload.at_hash).to.equal('tGwJZ3NDJh8LQ5pHJCIiXg')
            expect(token.payload.c_hash).to.equal('OAO0dgmipGQFRlmxSgzfug')
            expect(token.payload.cnf).to.eql({ jwk: cnfKey })
          })
      })
    })
  })

  describe('issue()', () => {
    let options

    beforeEach(() => {
      options = {
        aud: 'client123',
        azp: 'client123',
        sub: 'user123',
        nonce: 'n0nce',
        at_hash: 'athash123',
        c_hash: 'chash123',
        cnf: { jwk: {} }
      }
    })

    it('should issue an id token', () => {
      let token = IDToken.issue(provider, options)

      expect(token.payload.iss).to.equal(provider.issuer)
      expect(token.payload.aud).to.equal('client123')
      expect(token.payload.azp).to.equal('client123')
      expect(token.payload.sub).to.equal('user123')
      expect(token.payload.nonce).to.equal(options.nonce)
      expect(token.payload.at_hash).to.equal(options.at_hash)
      expect(token.payload.c_hash).to.equal(options.c_hash)
      expect(token.payload.cnf).to.eql(options.cnf)
    })

    it('should issue an id token with passed in values', () => {
      options.alg = 'RS512'

      let randomId = IDToken.random(8)
      options.jti = randomId

      let now = Math.floor(Date.now() / 1000)
      options.iat = now

      options.max = 3000

      let token = IDToken.issue(provider, options)

      expect(token.payload.jti).to.equal(randomId)
      expect(token.payload.iat).to.equal(now)
      expect(token.payload.exp - token.payload.iat).to.equal(3000)

      expect(token.header.alg).to.equal('RS512')
    })

    it('should init with defaults', () => {
      let token = IDToken.issue(provider, options)

      expect(token.header.alg).to.equal(IDToken.DEFAULT_SIG_ALGORITHM)
      expect(token.header.kid).to.exist()

      expect(token.payload.jti).to.exist()
      expect(token.payload.exp).to.exist()
      expect(token.payload.iat).to.exist()

      expect(token.payload.exp - token.payload.iat)
        .to.equal(IDToken.DEFAULT_MAX_AGE)

      expect(token.key).to.exist()
    })
  })
})
