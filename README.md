# DNSSEC-HSTS

DNSSEC-HSTS is a WebExtension that upgrades HTTP to HTTPS (simulating HSTS) for websites that support DANE (i.e. websites that list a TLSA record for TCP port 443).  This is a reasonably good heuristic for preventing sslstrip-style attacks.

**This code is experimental.**

## Installation

### Firefox

You'll first need to install the [native (Go) component](https://github.com/namecoin/dnssec-hsts-native) of DNSSEC-HSTS.  Then install DNSSEC-HSTS in Firefox as you would any other WebExtension.

### Chromium

You'll first need to install [certdehydrate-dane-rest-api](https://github.com/namecoin/certdehydrate-dane-rest-api).  Then install DNSSEC-HSTS in Firefox as you would any other WebExtension.

### Other browsers

I have no idea whether DNSSEC-HSTS works in browsers besides Firefox and Chromium.  Test reports welcome!

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
