/*
Copyright 2017-2019 Jeremy Rand.

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

function queryUpgradeNative(requestDetails, resolve, reject) {
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
}

// upgradeAsync function returns a Promise
// which is resolved with the upgrade after the native DNSSEC app replies
function upgradeAsync(requestDetails) {
  var asyncCancel = new Promise((resolve, reject) => {
    queryUpgradeNative(requestDetails, resolve, reject);
  });

  return asyncCancel;
}

// Adapted from Tagide/chrome-bit-domain-extension
// Returns true if timed out, returns false if hostname showed up
function sleep(milliseconds, hostname) {
  // synchronous XMLHttpRequests from Chrome extensions are not blocking event handlers. That's why we use this
  // pretty little sleep function to try to get the IP of a .bit domain before the request times out.
  var start = new Date().getTime();
  for (var i = 0; i < 1e7; i++) {
    if ((new Date().getTime() - start) > milliseconds) {
      return true;
    }
    if (sessionStorage.getItem(hostname) != null) {
      return false;
    }
  }
}

// Compatibility for Chromium, which doesn't support async onBeforeRequest
// See Chromium Bug 904365
function upgradeSync(requestDetails) {
  const url = new URL(requestDetails.url);
  const host = url.host;
  const hostname = url.hostname;
  const port = url.port;

  var certResponse;

  var upgrade = false;
  var lookupError = false;

  // Adapted from Tagide/chrome-bit-domain-extension
  // This .bit domain is not in cache, get the IP from dotbit.me
  var xhr = new XMLHttpRequest();
  var apiUrl = "http://127.0.0.1:8080/lookup?domain="+encodeURIComponent(hostname);
  // synchronous XMLHttpRequest is actually asynchronous
  // check out https://developer.chrome.com/extensions/webRequest
  xhr.open("GET", apiUrl, false);
  xhr.onreadystatechange = function() {
    if (xhr.readyState == 4) {
      if (xhr.status != 200) {
        console.log("Error received from API: status " + xhr.status);
        lookupError = true;
      }

      // Get the ip address returned from the DNS proxy server.
      certResponse = xhr.responseText;
      // store the IP for .bit hostname in the local cache which is reset on each browser restart
      sessionStorage.setItem(hostname, certResponse);
    }
  }
  try {
    xhr.send();
  } catch (e) {
    console.log("Error reaching API: " + e.toString());
    lookupError = true;
  }
  // block the request until the new proxy settings are set. Block for up to two seconds.
  if (sleep(2000, hostname)) {
    console.log("API timed out");
    lookupError = true;
  }

  // Get the IP from the session storage.
  var result = certResponse;
  if (result.trim() != "") {
    console.log("Upgraded via TLSA: " + host);
    upgrade = true;
  }

  return buildBlockingResponse(url, upgrade, lookupError);
}

function upgradeCompat(requestDetails) {
  if (onFirefox()) {
    return upgradeAsync(requestDetails);
  } else {
    return upgradeSync(requestDetails);
  }
}

function buildBlockingResponse(url, upgrade, lookupError) {
  if (lookupError) {
    return {"redirectUrl": compatBrowser.runtime.getURL("/pages/lookup_error/index.html")};
  }
  if (upgrade) {
    if (onFirefox()) {
      return {"upgradeToSecure": true};
    }
    url.protocol = "https:";
    // Chromium and Edge don't support "upgradeToSecure", so we use "redirectUrl" instead
    return {"redirectUrl": url.toString()};
  }
  return {};
}

// Only use this on initial extension startup; afterwards you should use
// resetRequestListener instead.
function attachRequestListener() {
  // This shim function is a hack so that we can add a new listener before we
  // remove the old one.  In theory JavaScript's single-threaded nature makes
  // that irrelevant, but I don't trust browsers to behave sanely on this.
  currentRequestListener = function(requestDetails) {
    return upgradeCompat(requestDetails);
  };

  // add the listener,
  // passing the filter argument and "blocking"
  compatBrowser.webRequest.onBeforeRequest.addListener(
    currentRequestListener,
    {urls: [buildPattern(matchHost)]},
    ["blocking"]
  );
}

// Attaches a new listener based on the current matchHost, and then removes the
// old listener.  The ordering is intended to prevent race conditions where the
// protection is disabled.
function resetRequestListener() {
  var oldListener = currentRequestListener;

  attachRequestListener();

  compatBrowser.webRequest.onBeforeRequest.removeListener(oldListener);
}

// Builds a match pattern for all HTTP URL's for the specified host
function buildPattern(host) {
  return "http://" + host + "/*";
}

// Based on https://stackoverflow.com/a/45985333
function onFirefox() {
  if (typeof chrome !== "undefined" && typeof browser !== "undefined") {
    return true;
  }
  return false;
}

console.log("Testing for Firefox: " + onFirefox());

var compatBrowser;
// Firefox supports both browser and chrome; Chromium only supports chrome;
// Edge only supports browser.  See https://stackoverflow.com/a/45985333
if (typeof browser !== "undefined") {
  console.log("Testing for browser/chrome: browser");
  compatBrowser = browser;
} else {
  console.log("Testing for browser/chrome: chrome");
  compatBrowser = chrome;
}

// Only used with native messaging
var nativePort;
var pendingUpgradeChecks = new Map();

// host for match pattern for the URLs to upgrade
var matchHost = "*.bit";
var currentRequestListener;

// Firefox is the only browser that supports async onBeforeRequest, and
// therefore is the only browser that we can use native messaging with.
if (onFirefox()) {
  /*
  On startup, connect to the Namecoin "dnssec_hsts" app.
  */
  nativePort = compatBrowser.runtime.connectNative("org.namecoin.dnssec_hsts");

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
      item(buildBlockingResponse(null, hasTLSA, !ok));
    }

    pendingUpgradeChecks.delete(host);
  });
}

attachRequestListener();
