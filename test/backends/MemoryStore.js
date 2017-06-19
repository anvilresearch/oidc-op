/**
 * Dependencies
 */

/**
 * MemoryStore
 */
class MemoryStore {

  /**
   * constructor
   */
  constructor (data = {}) {
    this.data = data
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
    let coll = this.data[collection]

    if (!coll) {
      return Promise.reject(new Error(`Unknown collection "${collection}"`))
    }

    return Promise.resolve(coll[key] || null)
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
    let coll = this.data[collection]

    if (!coll) {
      coll = this.data[collection] = {}
    }

    return Promise.resolve(coll[key] = value)
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
    let coll = this.data[collection]

    if (!coll) {
      return Promise.reject(new Error(`Unknown collection "${collection}"`))
    }

    delete coll[key]
    return Promise.resolve(true)
  }

}

/**
 * Export
 */
module.exports = MemoryStore
