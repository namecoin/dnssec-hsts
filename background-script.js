/*
Copyright 2017-2018 Jeremy Rand.

This file is part of DNSSEC-HSTS.

DNSSEC-HSTS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DNSSEC-HSTS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DNSSEC-HSTS.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
On startup, connect to the "dnssec_hsts" app.
*/
var nativePort = browser.runtime.connectNative("dnssec_hsts");

// match pattern for the URLs to upgrade
var pattern = "http://*/*";

var pendingUpgradeChecks = new Map();

// upgradeAsync function returns a Promise
// which is resolved with the upgrade after the native DNSSEC app replies
function upgradeAsync(requestDetails) {
  var asyncCancel = new Promise((resolve, reject) => {
    const url = new URL(requestDetails.url);
    const host = url.host;
    const hostname = url.hostname;
    const port = url.port;
    if(! pendingUpgradeChecks.has(host)) {
      pendingUpgradeChecks.set(host, new Set());

      const message = {"host": host, "hostname": hostname, "port": port};

      // Send message to the native DNSSEC app
      nativePort.postMessage(message);
    }
    pendingUpgradeChecks.get(host).add(resolve);
  });

  return asyncCancel;
}

/*
Listen for messages from the native DNSSEC app.
*/
nativePort.onMessage.addListener((response) => {
  const host = response["host"];
  const hasTLSA = response["hasTLSA"];
  const ok = response["ok"];

  if (!ok) {
    console.log("Native DNSSEC app error: " + host);
  }

  if(! pendingUpgradeChecks.has(host)) {
    return;
  }

  for (let item of pendingUpgradeChecks.get(host)) {
    if (hasTLSA) {
      item({upgradeToSecure: true});
      console.log("Upgraded via TLSA: " + host);
    } else {
      item({});
    }
  }

  pendingUpgradeChecks.delete(host);
});

// add the listener,
// passing the filter argument and "blocking"
browser.webRequest.onBeforeRequest.addListener(
  upgradeAsync,
  {urls: [pattern]},
  ["blocking"]
);
