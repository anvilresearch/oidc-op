
var crypto = require('crypto')

var enc = 'DavwvQbg7vL5lzylQQEcIom/f0Q8rCWiYTRZIrYz3gva40avskX/p0F8BqmVZZwAKr03TJ4dbQm17YRFLICYkLSsE3kDxIPZzLcchDjDU6wjDH762ahZ4QDQhMgPg9IbtyUjB1+jknvBN0FawXoWUFzHVskHdhcniyvu+5kIynnzLbXZ2m9Z0h0SybGhai60FG1JHd4YKpeaDJp2J9YFj4ZVv/viG5kNelBJoiJ4QikZvFiGI2kWqkli3bBmIeIkVIu2jmr00NytaZqbxNU1yXwZHQ0y3J1f/jG8256z7cXcULDrEV8EgvCtTSaeLWcJ1uQ2Komzwn8+XFfRtmiunQ=='
var buf = new Buffer(enc, 'base64')
console.log('DECODE', buf.toString('utf-8'))

const alice = crypto.createDiffieHellman(2048);
// const alice_key = alice.generateKeys('base64');
alice.setPrivateKey(enc, 'base64')

console.log('prime', alice.getPrime('base64'))

// console.log(alice_key)