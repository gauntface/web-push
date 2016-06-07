const urlBase64 = require('urlsafe-base64');
const crypto    = require('crypto');
const ece       = require('http_ece');
const url       = require('url');
const https     = require('https');
const colors    = require('colors');
const asn1      = require('asn1.js');
const jws       = require('jws');
const jwkToPem = require('jwk-to-pem');
require('./shim');

var ECPrivateKeyASN = asn1.define('ECPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid().optional(),
    this.key('publicKey').explicit(1).bitstr().optional()
  )
});

function toPEM(privateKey) {
  return ECPrivateKeyASN.encode({
    version: 1,
    privateKey: privateKey,
    parameters: [1, 2, 840, 10045, 3, 1, 7], // prime256v1
  }, 'pem', {
    label: 'EC PRIVATE KEY',
  });
}

function generateVAPIDKeys() {
  var curve = crypto.createECDH('prime256v1');
  curve.generateKeys();

  return {
    publicKey: curve.getPublicKey(),
    privateKey: curve.getPrivateKey(),
  };
}

function getVapidHeaders(vapid) {
  if (!vapid.audience) {
    throw new Error('No audient set');
  }

  if (!vapid.subject) {
    throw new Error('No subject set');
  }

  if (!vapid.publicKey) {
    throw new Error('No publicKey set');
  }

  if (!vapid.privateKey) {
    throw new Error('No privateKey set');
  }

  var tokenHeader = {
    typ: 'JWT',
    alg: 'ES256'
  };

  // The `exp` field will contain the current timestamp in UTC plus twelve hours.
  var tokenBody = {
    aud: vapid.audience,
    exp: vapid.expiration ? vapid.expiration :
      (Math.floor((Date.now() / 1000) + 12 * 60 * 60)),
    sub: vapid.subject,
  };

  var privatePEM = jwkToPem({
      crv: 'P-256',
      kty: 'EC',
      x: urlBase64.encode(vapid.publicKey.slice(1, 33)),
      y: urlBase64.encode(vapid.publicKey.slice(33, 65)),
      d: urlBase64.encode(vapid.privateKey)
  }, { private: true });

  /** console.log();
  console.log(privatePEM);
  console.log();
  console.log(toPEM(vapid.privateKey));
  console.log();**/

  var signObj = {
    header: tokenHeader,
    payload: tokenBody,
    privateKey: privatePEM
  };

  var jwt = jws.sign(signObj);

  console.log();
  console.log('Signed JWT', jwt);
  console.log();

  return {
    bearer: jwt,
    p256ecdsa: urlBase64.encode(vapid.publicKey)
  };
}

function WebPushError(message, statusCode, headers, body) {
  Error.captureStackTrace(this, this.constructor);

  this.name = this.constructor.name;
  this.message = message;
  this.statusCode = statusCode;
  this.headers = headers;
  this.body = body;
}

require('util').inherits(WebPushError, Error);

var gcmAPIKey = '';

function setGCMAPIKey(apiKey) {
  gcmAPIKey = apiKey;
}

// Old standard, Firefox 44+.
function encryptOld(userPublicKey, payload) {
  if (typeof payload === 'string' || payload instanceof String) {
    payload = new Buffer(payload);
  }
  var localCurve = crypto.createECDH('prime256v1');

  var localPublicKey = localCurve.generateKeys();
  var localPrivateKey = localCurve.getPrivateKey();

  var sharedSecret = localCurve.computeSecret(urlBase64.decode(userPublicKey));

  var salt = urlBase64.encode(crypto.randomBytes(16));

  ece.saveKey('webpushKey', sharedSecret);

  var cipherText = ece.encrypt(payload, {
    keyid: 'webpushKey',
    salt: salt,
    padSize: 1, // use the aesgcm128 encoding until aesgcm is well supported
  });

  return {
    localPublicKey: localPublicKey,
    salt: salt,
    cipherText: cipherText,
  };
}

// New standard, Firefox 46+ and Chrome 50+.
function encrypt(userPublicKey, userAuth, payload) {
  if (typeof payload === 'string' || payload instanceof String) {
    payload = new Buffer(payload);
  }
  var localCurve = crypto.createECDH('prime256v1');
  var localPublicKey = localCurve.generateKeys();

  var salt = urlBase64.encode(crypto.randomBytes(16));

  ece.saveKey('webpushKey', localCurve, 'P-256');

  var cipherText = ece.encrypt(payload, {
    keyid: 'webpushKey',
    dh: userPublicKey,
    salt: salt,
    authSecret: userAuth,
    padSize: 2,
  });

  return {
    localPublicKey: localPublicKey,
    salt: salt,
    cipherText: cipherText,
  };
}

function sendNotification(endpoint, params) {
  var args = arguments;

  if (args.length === 0) {
    return Promise.reject(new Error('sendNotification requires at least one argument, the endpoint URL'));
  }

  return new Promise(function(resolve, reject) {
    try {
      if (params && typeof params === 'object') {
        var TTL = params.TTL;
        var userPublicKey = params.userPublicKey;
        var userAuth = params.userAuth;
        var payload = params.payload;
        var vapid = params.vapid;
      } else if (args.length !== 1) {
        var TTL = args[1];
        var userPublicKey = args[2];
        var payload = args[3];
        console.warn('You are using the old, deprecated, interface of the `sendNotification` function.'.bold.red);
      }

      if (userPublicKey) {
        if (typeof userPublicKey !== 'string') {
          throw new Error('userPublicKey should be a base64-encoded string.');
        } else if (urlBase64.decode(userPublicKey).length !== 65) {
          throw new Error('userPublicKey should be 65 bytes long.');
        }
      }

      if (userAuth) {
        if (typeof userAuth !== 'string') {
          throw new Error('userAuth should be a base64-encoded string.');
        } else if (urlBase64.decode(userAuth).length < 16) {
          throw new Error('userAuth should be at least 16 bytes long');
        }
      }

      var urlParts = url.parse(endpoint);
      var options = {
        hostname: urlParts.hostname,
        port: urlParts.port,
        path: urlParts.pathname,
        method: 'POST',
        headers: {
          'Content-Length': 0,
        }
      };

      var requestPayload;
      if (typeof payload !== 'undefined') {
        var encrypted;
        var encodingHeader;
        var cryptoHeaderName;
        if (userAuth) {
          // Use the new standard if userAuth is defined (Firefox 46+ and Chrome 50+).
          encrypted = encrypt(userPublicKey, userAuth, payload);
          encodingHeader = 'aesgcm';
          cryptoHeaderName = 'Crypto-Key';
        } else {
          // Use the old standard if userAuth isn't defined (up to Firefox 45).
          encrypted = encryptOld(userPublicKey, payload);
          encodingHeader = 'aesgcm128';
          cryptoHeaderName = 'Encryption-Key';
        }

        options.headers = {
          'Content-Type': 'application/octet-stream',
          'Content-Encoding': encodingHeader,
          'Encryption': 'keyid=p256dh;salt=' + encrypted.salt,
        };

        options.headers[cryptoHeaderName] = 'keyid=p256dh;dh=' + urlBase64.encode(encrypted.localPublicKey);

        requestPayload = encrypted.cipherText;
      }

      const isGCM = endpoint.indexOf('https://android.googleapis.com/gcm/send') === 0;
      if (isGCM) {
        if (!gcmAPIKey) {
          console.warn('Attempt to send push notification to GCM endpoint, but no GCM key is defined'.bold.red);
          throw new Error('No GCM api key set for a GCM endpoint. Please use setGCMAPIKey().');
        }

        options.headers['Authorization'] = 'key=' + gcmAPIKey;
      }

      if (vapid && !isGCM && (typeof payload === 'undefined' || 'Crypto-Key' in options.headers)) {
        // VAPID isn't supported by GCM.
        // We also can't use it when there's a payload on Firefox 45, because
        // Firefox 45 uses the old standard with Encryption-Key.

        vapid.audience = urlParts.protocol + '//' + urlParts.hostname;
        vapid.subject = 'mailto:this.is.bad@someemail.com';

        var vapidHeaders = getVapidHeaders(vapid);
        options.headers['Authorization'] = 'Bearer ' + vapidHeaders.bearer;
        if (options.headers['Crypto-Key']) {
          options.headers['Crypto-Key'] += ',' + 'p256ecdsa=' + vapidHeaders.p256ecdsa;
        } else {
          options.headers['Crypto-Key'] = 'p256ecdsa=' + vapidHeaders.p256ecdsa;
        }
      }

      if (typeof TTL !== 'undefined') {
        options.headers['TTL'] = TTL;
      } else {
        options.headers['TTL'] = 2419200; // Default TTL is four weeks.
      }

      if (requestPayload) {
        options.headers['Content-Length'] = requestPayload.length;
      }

      var pushRequest = https.request(options, function(pushResponse) {
        var body = "";

        pushResponse.on('data', function(chunk) {
          body += chunk;
        });

        pushResponse.on('end', function() {
          if (pushResponse.statusCode !== 201) {
            reject(new WebPushError('Received unexpected response code', pushResponse.statusCode, pushResponse.headers, body));
          } else {
            resolve(body);
          }
        });
      });

      if (requestPayload) {
        pushRequest.write(requestPayload);
      }

      pushRequest.end();

      pushRequest.on('error', function(e) {
        console.error(e);
        reject(e);
      });
    } catch (e) {
      reject(e);
    }
  });
}

module.exports = {
  encryptOld: encryptOld,
  encrypt: encrypt,
  sendNotification: sendNotification,
  setGCMAPIKey: setGCMAPIKey,
  WebPushError: WebPushError,
  getVapidHeaders: getVapidHeaders,
  generateVAPIDKeys: generateVAPIDKeys,
};
