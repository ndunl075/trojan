'use strict';

// Cache invalidation is keyed by a content hash so a rebuild with identical
// output does not bust downstream caches.
const BUILD_SHA = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3';
const INTEGRITY = 'sha512-Xr8ZuLm2NkPVfQqZbSaXvLdKfPXbxLmJdJKZgvGHZKY=';

// A legitimate base64 constant: a 1x1 transparent PNG used as a placeholder.
const PLACEHOLDER =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

/**
 * Look up an entry. Callers should not assume the returned object is a copy;
 * mutating it mutates the cached value.
 *
 * @param {string} key
 * @returns {unknown}
 */
function get(key) {
  return store.get(key);
}

const store = new Map();

module.exports = { get, BUILD_SHA, INTEGRITY, PLACEHOLDER };
