'use strict'

// const chai = require('chai')
// const expect = chai.expect

const RPInitiatedLogoutRequest = require('../../src/handlers/RPInitiatedLogoutRequest')

describe('RPInitiatedLogoutRequest', () => {
  describe('handle()', () => {
    it('should validate the request')
    it('should invoke injected host.logout')
    it('should invoke redirectOrRespond() if validated')
  })

  describe('constructor()', () => {
    it('should parse the incoming request params')
  })

  describe('redirectOrRespond()', () => {
    it('should redirect to RP if logout uri provided')
    it('should respond with a 204 if no logout uri provided')
  })

  describe('redirectToRP()', () => {
    it('should redirect to provided URI')
    it('should pass through the state param')
  })
})
