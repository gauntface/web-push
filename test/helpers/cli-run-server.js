var webPush = require('../../index');
var createServer = require('./create-server');
var urlBase64 = require('urlsafe-base64');
var fs           = require('fs');

var VAPID = {
  public: 'BCkFDkye4m-ogGYUQyj-Z9975u1r0xgOApNpFVwWP1AoGOkvedxiTtDOze-d3DOel6dxws48bujRxhWc59cNclM',
  private: 'x3AfXDRFD3zTttp80wA_2DJ1MVYVYkeIkOiW-bt7RNI'
};
createServer({}, webPush, subscription => {
  webPush.sendNotification(subscription.endpoint, {
    vapid: {
      publicKey: urlBase64.decode(VAPID.public),
      privateKey: urlBase64.decode(VAPID.private)
    }
  })
  .then(() => {
    console.log('YAY Done.');
  })
  .catch(err => {
    console.log('Error', err);
  });
})
.then(server => {
  var testUrl = 'http://127.0.0.1:' + server.port + '?vapid=' + VAPID.public;
  console.log(testUrl);
});
