var assert = require('assert');
var url = require('url');
var urlBase64 = require('urlsafe-base64');
var webPush = require('../index');
var createServer = require('./helpers/create-server');
var isPortOpen = require('./helpers/port-open');

webPush.setGCMAPIKey('AIzaSyAwmdX6KKd4hPfIcGU2SOfj9vuRDW6u-wo');

process.env.PATH = process.env.PATH + ':test_tools/';

suite('selenium', function() {
  this.timeout(180000);

  var invalidNodeVersions = /0.(10|12).(\d+)/;
  if (process.versions.node.match(invalidNodeVersions)) {
    console.log('Skipping selenium tests as they can\'t run on ' + process.versions.node);
    return;
  }

  var webdriver = require('selenium-webdriver');
  var firefoxBrowsers = require('./browser-managers/firefox-browsers.js');
  var chromeBrowsers = require('./browser-managers/chrome-browsers.js');

  var vapidKeys = webPush.generateVAPIDKeys();

  const VAPID_PARAM = {
    subject: 'mailto:web-push@mozilla.org',
    privateKey: vapidKeys.privateKey,
    publicKey: vapidKeys.publicKey,
  };
  var globalServer, globalDriver;

  suiteSetup(function() {
    this.timeout(0);

    var promises = [];
    promises.push(firefoxBrowsers.downloadDependencies());
    promises.push(chromeBrowsers.downloadDependencies());

    return Promise.all(promises)
    .then(function() {
      console.log('');
      console.log('');
      console.log('     Suite setup complete');
      console.log('');
      console.log('');
    });
  });

  teardown(function(done) {
    var closeDriverPromise = Promise.resolve();
    if (globalDriver) {
      closeDriverPromise = new Promise(function(resolve) {
        globalDriver.quit()
        .then(function() {
          resolve();
        })
        .thenCatch(function(err) {
          console.log('Error when quiting driver: ', err);
          resolve();
        })
      });
    }

    closeDriverPromise
    .then(function() {
      globalDriver = null;
      globalServer.close(function() {
        globalServer = null;
        done();
      });
    });
  });

  function runTest(driverFunction, options) {
    options = options ? options : {};

    return createServer(options, webPush)
    .then(function(server) {
      globalServer = server;
      return driverFunction();
    })
    .then(function(driver) {
      globalDriver = driver;
      // Tests will likely expect a native promise with then and catch
      // Not the web driver promise of then and thenCatch
      return new Promise(function(resolve, reject) {
        var testUrl = 'http://127.0.0.1:' + globalServer.port;
        if (options.vapid) {
          testUrl += '?vapid=' + urlBase64.encode(options.vapid.publicKey);
        }

        globalDriver.get(testUrl)
        .then(function() {
          return globalDriver.executeScript(function() {
            return typeof navigator.serviceWorker !== 'undefined';
          });
        })
        .then(function(serviceWorkerSupported) {
          assert(serviceWorkerSupported);
        })
        .then(function() {
          return globalDriver.executeScript(function(port) {
            if (typeof netscape !== 'undefined') {
              netscape.security.PrivilegeManager.enablePrivilege('UniversalXPConnect');
              Components.utils.import('resource://gre/modules/Services.jsm');
              var uri = Services.io.newURI('http://127.0.0.1:' + port, null, null);
              var principal = Services.scriptSecurityManager.getNoAppCodebasePrincipal(uri);
              Services.perms.addFromPrincipal(principal, 'desktop-notification', Services.perms.ALLOW_ACTION);
            }
          }, globalServer.port);
        })
        .then(function() {
          return globalDriver.wait(function() {
            return globalDriver.executeScript(function() {
              return typeof window.subscribeSuccess !== 'undefined';
            });
          });
        })
        .then(function() {
          return globalDriver.executeScript(function() {
            if (!window.subscribeSuccess) {
              return window.subscribeError;
            }

            return null;
          });
        })
        .then(function(subscribeError) {
          if (subscribeError) {
            throw subscribeError;
          }

          return globalDriver.executeScript(function() {
            return window.testSubscription;
          });
        })
        .then(function(subscription) {
          if (!subscription) {
            throw new Error('No subscription found.');
          }

          var promise;
          var pushPayload = null;
          var vapid = null;
          if (options) {
            pushPayload = options.payload;
            vapid = options.vapid;
          }

          if (vapid) {
            vapid.audience = url.parse(subscription.endpoint).hostname;
          }

          if (!pushPayload) {
            promise = webPush.sendNotification(subscription.endpoint, {
              vapid: vapid,
            });
          } else {
            promise = webPush.sendNotification(subscription.endpoint, {
              payload: pushPayload,
              userPublicKey: subscription.key,
              userAuth: subscription.auth,
              vapid: vapid,
            });
          }

          return promise
          .then(function(response) {
            if (response.length > 0) {
              var data = JSON.parse(response);
              if (typeof data.failure !== 'undefined' && data.failure > 0) {
                throw new Error('Bad GCM Response: ' + response);
              }
            }

            //console.log('Push Application Server - Notification sent to ' + obj.endpoint);
          });
        })
        .then(function() {
          var expectedTitle = options.payload ? options.payload : 'no payload';
          return globalDriver.wait(webdriver.until.titleIs(expectedTitle, 60000));
        })
        .then(function() {
          resolve();
        })
        .thenCatch(function(err) {
          console.log(err);
          reject(err);
        });
      });
    });
  }

  var firefoxBrowsersToTest = [
    {
      id: 'firefox',
      name: 'Firefox Stable'
    }
    // 'firefox-beta',
    // 'firefox-aurora'
  ];

  var chromeBrowsersToTest = [
    {
      id: 'chrome',
      name: 'Chrome Stable'
    },
    {
      id: 'chrome-beta',
      name: 'Chrome Beta'
    },
    /**{
      id: 'chromium',
      name: 'Latest Chromium Build'
    }**/
  ];

  var browserDrivers = [];
  firefoxBrowsersToTest.forEach(function(browserInfo) {
    browserInfo.getBrowserDriver = function() {
      return firefoxBrowsers.getBrowserDriver(browserInfo.id);
    }
    browserDrivers.push(browserInfo);
  });

  if (process.env.TRAVIS_OS_NAME !== 'osx') {
    chromeBrowsersToTest.forEach(function(browserInfo) {
      browserInfo.getBrowserDriver = function() {
        return chromeBrowsers.getBrowserDriver(browserInfo.id, 'http://127.0.0.1:' + globalServer.port);
      }
      browserDrivers.push(browserInfo);
    });
  }

  browserDrivers.forEach(function(browserInfo) {
    test('send/receive notification without payload with ' + browserInfo.name, function() {
      return runTest(browserInfo.getBrowserDriver);
    });

    test('send/receive notification with payload with ' + browserInfo.name, function() {
      return runTest(browserInfo.getBrowserDriver, {
        payload: 'marco'
      });
    });

    test('send/receive notification with vapid with ' + browserInfo.name, function() {
      return runTest(browserInfo.getBrowserDriver, {
        vapid: VAPID_PARAM
      });
    });

    test('send/receive notification with payload & vapid with ' + browserInfo.name, function() {
      return runTest(browserInfo.getBrowserDriver, {
        payload: 'marco',
        vapid: VAPID_PARAM,
      });
    });
  });
});
