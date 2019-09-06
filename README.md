# DNSSEC-HSTS

DNSSEC-HSTS is a WebExtension that upgrades HTTP to HTTPS (simulating HSTS) for websites that support DANE (i.e. websites that list a TLSA record for TCP port 443).  This is a reasonably good heuristic for preventing sslstrip-style attacks.

**This code is experimental.**

## Build

### Firefox on GNU/Linux

Firefox accepts unpacked extensions; no build is needed.

### Firefox on non-GNU/Linux

~~~
git clone https://github.com/namecoin/dnssec-hsts.git
cd dnssec-hsts
zip dnssec-hsts@namecoin.org.xpi
~~~

### Tor Browser

Same as Firefox on non-GNU/Linux (even if you're on GNU/Linux).

### Chromium or Chrome (Unpacked)

~~~
git clone https://github.com/namecoin/dnssec-hsts.git
cd dnssec-hsts
./use-png-icon.sh
~~~

### Chromium or Chrome on GNU/Linux (Packed CRX)

* Follow "Chromium or Chrome (Unpacked)" above.
* Pack the extension via the Chromium Extensions UI (needs to be in Developer Mode).
    * Note that this step requires the DNSSEC-HSTS signing private key.
* Distribute the CRX that Chromium generated, as well as `ogimlildljgffpifafnhjggflenjhljf.json` from this repo.

## Installation

### Firefox on GNU/Linux

You'll first need to install the [native (Go) component](https://github.com/namecoin/dnssec-hsts-native) of DNSSEC-HSTS.

Then, from the `dnssec-hsts` directory:

~~~
sudo rm -rf /usr/share/webext/dnssec-hsts/
sudo cp -a . /usr/share/webext/dnssec-hsts
sudo ln -s -T /usr/share/webext/dnssec-hsts "/usr/share/mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/dnssec-hsts"
~~~

You may need to restart Firefox, and/or enable the extension in the Addons dialog.

### Firefox on non-GNU/Linux

* Install the [native (Go) component](https://github.com/namecoin/dnssec-hsts-native) of DNSSEC-HSTS.
* Disable XPI extension signature checking in Firefox.
* Open `dnssec-hsts@namecoin.org.xpi` in Firefox, and accept the extension installation dialog.

### Tor Browser

Follow the Firefox instructions for non-GNU/Linux OS's, even if you're on GNU/Linux.

### Chromium (not Chrome) on GNU/Linux (Unpacked, System-Wide)

You'll first need to install [certdehydrate-dane-rest-api](https://github.com/namecoin/certdehydrate-dane-rest-api).

Then, from the `dnssec-hsts` directory:

~~~
sudo rm -rf /usr/share/webext/dnssec-hsts/
sudo cp -a . /usr/share/webext/dnssec-hsts
sudo ln -s -T /usr/share/webext/dnssec-hsts /usr/share/chromium/extensions/dnssec-hsts
~~~

You may need to reboot Chromium afterwards.

### Chrome (not Chromium) on GNU/Linux (Packed, System-Wide)

You'll first need to install [certdehydrate-dane-rest-api](https://github.com/namecoin/certdehydrate-dane-rest-api).

Then run this:

~~~
sudo mkdir /usr/local/namecoin/ /usr/share/google-chrome/extensions/
sudo cp ./dnssec-hsts*.crx /usr/local/namecoin/dnssec-hsts.crx
sudo cp ./ogimlildljgffpifafnhjggflenjhljf.json /usr/share/google-chrome/extensions/
~~~

You may need to reboot Chrome afterwards.

### Chromium or Chrome (Unpacked, Developer Mode, Profile-Specific)

* Install [certdehydrate-dane-rest-api](https://github.com/namecoin/certdehydrate-dane-rest-api).
* Load the unpacked extension in the Chromium Extensions Developer Mode UI.

### Other browsers

I have no idea whether DNSSEC-HSTS works in browsers besides Firefox, Chromium, and Chrome.  Test reports welcome!

## Warnings

DNSSEC-HSTS trusts your DNS resolver, and the network path to it.  This is perfectly fine if your DNS resolver is running on localhost (e.g. if you've installed DNSSEC-Trigger locally), but this is definitely *not* a good idea if your DNS resolver is operated by your ISP.

## License

DNSSEC-HSTS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DNSSEC-HSTS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with DNSSEC-HSTS.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).

The Namecoin logo is licensed under the Creative Commons Attribution 4.0 International License. To view a copy of the license, visit [https://creativecommons.org/licenses/by/4.0/](https://creativecommons.org/licenses/by/4.0/).

The author strongly condemns the extension TiVoization implemented by certain versions of browsers such as Chrome and Firefox.  Although the GPLv3+ license permits you to use or distribute DNSSEC-HSTS in conjunction with extension TiVoization systems, the author will not provide support to users who engage in such practices.
