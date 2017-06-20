/**
 * Dependencies
 */
const fs = require('fs')
const path = require('path')

/**
 * JSONStore
 */
class JSONStore {

  /**
   * constructor
   */
  constructor (config) {
    this.path = config.path
  }

  /**
   * get
   *
   * @param {string} collection
   * @param {string} key
   *
   * @returns {Promise}
   */
  get (collection, key) {
    let directory = path.join(this.path, collection)
    let descriptor = path.join(directory, `${key}.json`)

    return new Promise((resolve, reject) => {
      fs.readFile(descriptor, (err, result) => {
        if (err) { return reject(err) }
        if (!result) { return resolve(null) }
        resolve(JSON.parse(result))
      })
    })
  }

  /**
   * put
   *
   * @param {string} collection
   * @param {string} key
   * @param {Object} value
   *
   * @returns {Promise}
   */
  put (collection, key, value) {
    let directory = path.join(this.path, collection)
    let descriptor = path.join(directory, `${key}.json`)

    return new Promise((resolve, reject) => {
      let data = JSON.stringify(value, null, 2)

      fs.writeFile(descriptor, data, (err) => {
        if (err) { return reject(err) }
        resolve(true)
      })
    })
  }

  /**
   * del
   *
   * @param {string} collection
   * @param {string} key
   *
   * @returns {Promise}
   */
  del (collection, key) {
    let directory = path.join(this.path, collection)
    let descriptor = path.join(directory, `${key}.json`)

    return new Promise((resolve, reject) => {
      fs.unlink(descriptor, (err) => {
        if (err) { return reject(err) }
        resolve(true)
      })
    })
  }

}

/**
 * Export
 */
module.exports = JSONStore
