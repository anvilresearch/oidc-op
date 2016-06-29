
let keypair = RSAKeyPair {
  pub: {
    jwk: RSAPublicKey,
    pem: '...'
  },
  prv: {
    jwk: RSAPrivateKey,
    pem: '...'
  }
}

class RSAKeyPair {
  
  constructor (opts) {
    if (opts.prv) {
      if (opts.prv.jwk) {
        this.prv.jwk = new RSAPrivateKey(opts.prv.jwk)
        // other logic

        if (!opts.prv.pem) {
          this.prv.pem = this.prv.jwk.toPEM()
        }
      }
    } else {
      throw new Error('etc')
    }
  }

  static generate () {
    return Promise.resolve(/* something */)
  }
}

class RSAPrivateKey {

  constructor (opts) {
    if (opts.pem && !opts.jwk) {
      let jwk = RSAPrivateKey.toJWK(opts.pem)
      // do something
    }
  }

  static toJWK (pem) {
    return jwk_object
  }

  toPEM () {
    return generated_pem_string
  }

  get pem () {
    if (!this._pem) {
      this._pem = this.toPEM()
    }
  }
}
