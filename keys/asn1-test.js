'use strict'

const fs = require('fs')
const crypto = require('crypto')
const asn = require('asn1.js')

const RSAPublicKey = asn.define('RSAPublicKey', function () {
  this.seq().obj(
    this.key('n').int(),
    this.key('e').int()
  )
})

const AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function () {
  this.seq().obj(
    this.key('algorithm').objid(),
    this.key('parameters').optional().any()
  )
})

const PublicKeyInfo = asn.define('PublicKeyInfo', function () {
  this.seq().obj(
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('publicKey').bitstr()
  )
})

const Version = asn.define('Version', function () {
  this.int({
    0: 'two-prime',
    1: 'multi'
  })
})

const OtherPrimeInfos = asn.define('OtherPrimeInfos', function () {
  this.seq().obj(
    this.key('ri').int(),
    this.key('di').int(),
    this.key('ti').int()
  )
})

const RSAPrivateKey = asn.define('RSAPrivateKey', function () {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dp').int(),
    this.key('dq').int(),
    this.key('qi').int(),
    this.key('other').optional().use(OtherPrimeInfos)
  )
})

const PrivateKeyInfo = asn.define('PrivateKeyInfo', function () {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('privateKey').bitstr()
  )
})

const RSA_OID = '1.2.840.113549.1.1.1'

function pad(hex) {
  return (hex.length % 2 === 1) ? '0' + hex : hex
}

function hex2b64url(str) {
  return urlize(Buffer(str, 'hex').toString('base64'))
}

function bn2base64url(bn) {
  return hex2b64url(pad(bn.toString(16)))
}

function base64url2bn(str) {
  return new asn.bignum(Buffer(str, 'base64'))
}

function urlize(base64) {
  return base64.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

function string2bn(str) {
  if (/^[0-9]+$/.test(str)) {
    return new asn.bignum(str, 10)
  }
  return base64url2bn(str)
}

function parse(jwk) {
  return {
    n: string2bn(jwk.n),
    e: string2bn(jwk.e),
    d: jwk.d && string2bn(jwk.d),
    p: jwk.p && string2bn(jwk.p),
    q: jwk.q && string2bn(jwk.q),
    dp: jwk.dp && string2bn(jwk.dp),
    dq: jwk.dq && string2bn(jwk.dq),
    qi: jwk.qi && string2bn(jwk.qi)
  }
}

let privateKey = fs.readFileSync('./private.pem', 'ascii')

function pem2jwk(pem) {
  let split = privateKey.split(/(\r\n|\r|\n)+/g)

  let filter = split.filter((line) => {
    return line.trim().length !== 0
  })

  // decode

  let joined = filter.slice(1, -1).join('')

  let decoderIn = new Buffer(joined.replace(/[^\w\d\+\/=]+/g, ''), 'base64')

  let key = RSAPrivateKey.decode(decoderIn, 'der')
  let e = pad(key.e.toString(16))
  return {
    kty: 'RSA',
    n: bn2base64url(key.n),
    e: hex2b64url(e),
    d: bn2base64url(key.d),
    p: bn2base64url(key.p),
    q: bn2base64url(key.q),
    dp: bn2base64url(key.dp),
    dq: bn2base64url(key.dq),
    qi: bn2base64url(key.qi)
  }
}

function jwk2pem(json) {
  let jwk = parse(json)
  let isPrivate = Boolean(jwk.d)
  let t = 'PRIVATE'
  let header = '-----BEGIN RSA ' + t + ' KEY-----\n'
  let footer = '\n-----END RSA ' + t + ' KEY-----'
  let data = Buffer(0)

  jwk.version = 'two-prime'
  data = RSAPrivateKey.encode(jwk, 'der')
  
  let body = data.toString('base64').match(/.{1,64}/g).join('\n')
  return header + body + footer
}

console.log(jwk2pem(pem2jwk(privateKey)))