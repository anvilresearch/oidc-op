'use strict'

/**
 * Used to break flow control out of long promise chains. See usages in
 * `handlers/BaseRequest.js`.
 *
 * @class
 * @extends Error
 */
class HandledError extends Error {
  /**
   * @param message {string}
   */
  constructor (message) {
    super(message)

    this.handled = true
  }
}

module.exports = HandledError
