var webPush = require('../../index');
var createServer = require('./create-server');
var urlBase64 = require('urlsafe-base64');

var VAPID = {
  public: 'BBCfX1ZO2Ckjasb99j1HzG-mI8S2f9IuBrGBqnlFImpYydnHJE6JjihdTZONYNv6oUCOG8z15jqstfVJZvwq-C4',
  private: '1BScQihYj68cZcgwtMDEoJD55c8Fv9DgCBLNLE7FeG0'
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
