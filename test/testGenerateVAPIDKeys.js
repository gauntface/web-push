var assert    = require('assert');
var crypto    = require('crypto');
var webPush   = require('../index');
var fs        = require('fs');

suite('vapid', function() {
  var VALID_VAPID_KEYS = {
    publicKey: 'BG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f-fhsQ5pK8',
    privateKey: 'Dt1CLgQlkiaA-tmCkATyKZeoF1-Gtw1-gdEP6pOCqj4'
  };

  var VALID_OUTPUT = {
    expiration: 1464326106,
    unsignedToken: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsImV4cCI6MTQ2NDMyNjEwNiwic3ViIjoibWFpbHRvOndlYi1wdXNoQG1vemlsbGEub3JnIn0',
    p256ecdsa: 'BG3OGHrl3YJ5PHpl0GSqtAAlUPnx1LvwQvFMIc68vhJU6nIkRzPEqtCduQz8wQj0r71NVPzr7ZRk2f-fhsQ5pK8'
  };

  test('is defined', function() {
    assert(webPush.generateVAPIDKeys);
  });

  test('generate keys', function() {
    var keys = webPush.generateVAPIDKeys();
    assert(keys.privateKey);
    assert(keys.publicKey);
  });

  test('vapid headers', function() {
    return webPush.getVapidHeaders({
      publicKey: new Buffer(VALID_VAPID_KEYS.publicKey, 'base64'),
      privateKey: new Buffer(VALID_VAPID_KEYS.privateKey, 'base64'),
      audience: 'https://fcm.googleapis.com',
      expiration: VALID_OUTPUT.expiration,
      subject: 'mailto:web-push@mozilla.org'
    })
    .then(vapidHeaders => {
      assert(vapidHeaders instanceof Object);
      assert(typeof vapidHeaders.bearer === 'string');
      assert(typeof vapidHeaders.p256ecdsa === 'string');

      assert(vapidHeaders.p256ecdsa === VALID_OUTPUT.p256ecdsa);
      assert(vapidHeaders.bearer.indexOf(VALID_OUTPUT.unsignedToken) === 0);
    });
  });
});
