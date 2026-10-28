# What is in this package

Guardian 1.1.2, 30 files.

Unzip it, then load the folder through chrome://extensions with Developer
mode turned on and "Load unpacked". Nothing needs building.

## Checks you can run without a browser

    node test-pages/selftest-node.js    the false-positive guarantees
    node test-pages/check-refs.js       every function called is defined
    node test-pages/check-ui.js         popup and warning structure
    node test-pages/check-worker.js     service worker behaviour
    node test-pages/check-warnings.js   warning ladder and impersonation
    node test-pages/check-firstrun.js   a brand-new install, and hangs

test-pages/neutralizer-selftest.html is the browser half: open it and the
title should read PASS.

## Deliberately not included

README.md and SETUP.md mention some of these. They are in the source
repository, not in this package.

- NOTES.md
- TODO.md
- demo/guardian-demo.html
- practice/guardian-practice.html
- practice/practice.css
- practice/practice.html
- practice/practice.js
- practice/scenarios.js
- test-pages/check-practice.js
- test-pages/fake-bitb-login.html
- test-pages/fake-brand-hostname-login.html
- test-pages/fake-download-portal.html
- test-pages/fake-google-login.html
- test-pages/fake-package-phish.html
- test-pages/fake-typosquat-login.html
- test-pages/fake-virus-alert.html
- test-pages/reported-scam-site.html
- tools/build-practice.js
- tools/package.js

The fake-*.html and reported-scam-site.html files are practice pages that
imitate phishing sign-in forms and scam alerts. They are safe to open, but
they look exactly like what antivirus software is built to catch, and a zip
that trips a scanner does not get read. demo/guardian-demo.html is a
presentation reel, not part of the extension. NOTES.md and TODO.md are
working notes.
