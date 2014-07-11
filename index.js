var jws = require('jws');

// CUSTOM ERRORS

function TokenExpired(msg) {
  this.message = msg;
  this.canBeRenewed = false;
  this.stack = (new Error()).stack;
}

TokenExpired.prototype = new Error;
TokenExpired.prototype.name = 'TokenExpired';

function TokenInvalid(msg) {
  this.message = msg;
  this.canBeRenewed = false;
  this.stack = (new Error()).stack;
}

TokenInvalid.prototype = new Error;
TokenInvalid.prototype.name = 'TokenInvalid';

module.exports.errors = {
  TokenExpired: TokenExpired,
  TokenInvalid: TokenInvalid
};

// end CUSTOM ERRORS

module.exports.decode = function (jwt) {
  return jws.decode(jwt).payload;
};

module.exports.sign = function(payload, secretOrPrivateKey, options) {
  options = options || {};

  var header = {typ: 'JWT', alg: options.algorithm || 'HS256'};

  payload.iat = Math.round(Date.now() / 1000);

  if (options.expiresInMinutes) {
    var ms = options.expiresInMinutes * 60;
    payload.exp = payload.iat + ms;
  }

  if (options.audience)
    payload.aud = options.audience;

  if (options.issuer)
    payload.iss = options.issuer;

  if (options.subject)
    payload.sub = options.subject;

  var signed = jws.sign({header: header, payload: payload, secret: secretOrPrivateKey});

  return signed;
};

module.exports.verify = function(jwtString, secretOrPublicKey, options, callback) {
  if ((typeof options === 'function') && !callback) callback = options;
  if (!options) options = {};

  var valid;
  try {
    valid = jws.verify(jwtString, secretOrPublicKey);
  }
  catch (e) {
    return callback(e);
  }

  if (!valid)
    return callback(new TokenInvalid('invalid signature'));

  var payload = this.decode(jwtString);

  if (payload.exp) {
    if (Math.round(Date.now()) / 1000 >= payload.exp)
      return callback(new TokenExpired('jwt expired'));
  }

  if (options.audience) {
    if (payload.aud !== options.audience)
      return callback(new TokenInvalid('jwt audience invalid. expected: ' + payload.aud));
  }

  if (options.issuer) {
    if (payload.iss !== options.issuer)
      return callback(new TokenInvalid('jwt issuer invalid. expected: ' + payload.iss));
  }

  callback(null, payload);
};
