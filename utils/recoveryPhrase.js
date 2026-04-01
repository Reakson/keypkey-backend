const crypto = require('crypto');

function generateRecoveryKey() {
  return crypto
    .randomBytes(16)
    .toString('hex')
    .match(/.{1,4}/g)
    .join('-')
    .toUpperCase();
}

module.exports = {
  generateRecoveryKey,
};