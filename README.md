# Guardian

A Chrome extension that protects seniors from scam websites and scam emails
with plain-language warnings. Everything runs locally in the browser: no
server, no cloud AI, no browsing data ever leaves the machine.

## What it does

- Scans every page you visit for tech-support scams ("your computer is
  infected, call this number"), fake prize pages, and phishing sites
  pretending to be brands like PayPal or Amazon
- Scans opened emails in Gmail (web) for the same scam patterns
- The warning is graduated, so it is not "all or nothing":
  - CONFIDENT scam: Guardian takes over the screen immediately, while the
    scam is still up. A full-screen red warning covers the scam content
    (including any fake phone number) with giant text and one big button,
    "Close this page". This works even if Chrome or Windows notifications
    are off, because it is drawn inside the page itself, and a Chrome
    notification also fires.
  - MIGHT be a scam (suspicious but not certain): just a slim amber caution
    strip at the top of the page ("this page might not be safe, be
    careful..."), which does NOT cover the page. If the on-device AI then
    confirms it is a scam, the strip escalates to the full warning; if the
    AI says it is safe, the strip goes away.
- If the scam page forced itself into fullscreen (a common trick to hide
  the browser bar), Guardian kicks it back out of fullscreen
- Remote-control tool sites (AnyDesk, TeamViewer, Chrome Remote Desktop
  and others) show a calm orange stop-and-think caution: "Is someone on
  the phone telling you to install this program? Hang up now." Phone
  scammers walking a victim through installing remote software is how
  bank accounts get emptied; nothing else on the market interrupts it.
- 18 interface languages: warnings, buttons and answers appear in the
  browser's language (English, Spanish, German, French, Italian,
  Portuguese, Dutch, Romanian, Polish, Russian, Arabic, Chinese, Japanese,
  Greek, Hungarian, Swedish, Danish, Norwegian). Keyword detection covers
  the major European languages, and the on-device AI tier understands scam
  context in essentially any language.
- Insecure sign-in warning: a page asking for a password over an
  unencrypted (non-HTTPS) connection is flagged.
- Report a scam: one button adds the current page to the person's own
  blocklist immediately and offers to forward it to a public database
  (Google Safe Browsing) that protects everyone.

## Compared to paid alternatives (e.g. GrannySafe, $99/year)

Guardian is free and does everything those do, plus more, with a stronger
privacy model (nothing ever leaves the machine). Point-by-point:

- Live threat database: yes (OpenPhish + URLhaus, refreshed on-device)
- AI page analysis: yes (Chrome's on-device Gemini Nano, given the domain
  and reputation signals, not just keywords)
- Reputation signals: yes, computed locally (look-alike domains, brand
  stuffing, risky TLDs, no-HTTPS). Domain age / external reputation is
  deliberately NOT queried because that would send the address off-device.
- 18 languages: yes
- 800+ trusted sites: 589 hand-picked domains PLUS every .gov, .mil and
  .edu site (tens of thousands), so effective coverage far exceeds 800
- One-click reporting: yes
- Warning only on real danger: measured on a balanced test (real fetched
  page content on both sides): the content engine flags ~42% of analyzable
  phishing pages while flagging 0% of legitimate sites. This is the content
  tier ALONE; the blocklist tier catches ~100% of already-reported scams
  instantly, and the on-device AI adds more in-browser.
- Privacy: stronger. GrannySafe can send alerts to a server; Guardian's
  detection is 100% local.
- Scam emails in Gmail get a large red warning banner directly above the
  email text. Emails are scored on their wording AND their links: a link
  to a reported phishing site flags instantly, and so does password/account
  language whose action link points to a credential-bait domain (like
  secured-login.net) that does not belong to the sender.
- Reputable sites (banks, big retailers, government sites) are on an
  allowlist and are NEVER flagged. No false alarms on real sites.
- The toolbar popup shows how many scams have been blocked (websites and
  emails, this week and all time) and has a big round "Is this a scam?"
  button: if the person is unsure about the page they are on, one press
  checks it (trusted list, reported-scam list, page scan, and the
  on-device AI when available) and answers in plain words: "This is a
  SCAM. Close this page." or "This page looks OK."

## Install (developer mode)

1. Open Chrome and go to chrome://extensions
2. Turn on "Developer mode" (top right toggle)
3. Click "Load unpacked" and select this folder (Guardian)
4. To test with the local demo pages: click "Details" on the Guardian
   extension and turn on "Allow access to file URLs"

## Demo script

1. Open test-pages/fake-virus-alert.html in Chrome
   - A notification fires and a red banner appears at the top of the page
   - Click "Close this page" and the tab closes
2. Open test-pages/fake-package-phish.html
   - Same treatment: this one is caught as a fake brand page asking for
     credentials
3. Open test-pages/fake-google-login.html
   - Caught as a cloned Google sign-in page: real Google login wording
     plus a password field on a domain that is not google.com
4. Open test-pages/fake-bitb-login.html
   - A browser-in-the-browser attack: a fake recruiter page that injects
     a fake Google sign-in "window" (with a fake painted address bar)
     into the same page after a click, or by itself after 6 seconds.
     Guardian re-scans on page changes and catches it when it appears.
5. Open test-pages/fake-typosquat-login.html
   - Caught as a typosquat: the page acts as paypa1.com (with the digit 1),
     one character away from paypal.com
6. Open test-pages/fake-brand-hostname-login.html
   - Caught because a brand name is planted in the address itself
     (secure-chase-login.com), not on the real chase.com
7. Open test-pages/reported-scam-site.html
   - Caught by the reported-scam blocklist even though the page has no
     scam wording at all: this is how quiet, professional-looking
     phishing pages get flagged
7b. Open test-pages/fake-download-portal.html
   - A Softonic-style download page with fake "Download" buttons and
     installer/keygen language. Guardian routes it to the on-device AI to
     judge (needs Chrome's Gemini Nano installed; otherwise nothing happens).
     EXACTLY TWO buttons are neutralized: one whose destination is on the
     threat feed (the strong "Fake download blocked by Guardian" wording,
     which a feed hit earns) and one pointing at a curated decoy network
     (the calmer "This is an advert, not the download"). The real download,
     and everything in the page's regression block, must be left completely
     alone. No full-page takeover, because the page itself is not a scam.
7c. Open test-pages/neutralizer-selftest.html
   - Asserts the false-positive guarantees directly against the real source
     (no extension needed). The title must read PASS. Its headless half runs
     as `node test-pages/selftest-node.js` and exits non-zero on any failure.
8. Browse normal sites (google.com, amazon.com, your bank)
   - Nothing happens. Zero false alarms by design.
9. Open anydesk.com
   - Orange stop-and-think caution: "Is someone on the phone telling you
     to install this program? Hang up now."
10. Click the Guardian icon in the toolbar
    - The dashboard shows the running count of scams blocked, plus the big
      "Is this a scam?" button

Notes on the demo pages: the last three declare a demo hostname via a
`<meta name="guardian-demo-hostname">` tag so the hostname-based checks
(typosquat, brand-in-hostname, blocklist) can be shown from a local file.
Guardian honors that tag only on `file://` pages, so a real web page can
never use it to weaken detection.

## Demo reel (for presentations)

`demo/guardian-demo.html` is a self-contained, auto-playing walkthrough of
every feature. Double-click it to open in a browser, then press Play. It
shows a mock browser stepping through each scam type with Guardian's real
response, because it loads the actual detection engine (data/ and content/
detector.js), so the verdicts and warnings are genuinely computed, not
faked. Use it to present live, or screen-record it to make a video.

To record it yourself on Windows: open the demo, press Win+Alt+R (the
built-in Xbox Game Bar recorder), press Play, and stop when it finishes.

> **If you are reading this inside a release zip:** the practice pages, the
> demo reel and the working notes referenced below are not in the package. See
> PACKAGE.md for exactly what was included and why. Everything described here
> is in the source repository.

## How detection works

Four tiers, in order:

1. Allowlist short-circuit: if the site is on the reputable-domains list
   (data/allowlist.js), Guardian does nothing. This guarantees zero false
   positives on major legitimate sites.
2. Reported-scam blocklist: the visited site is checked against a local
   merged copy of two public threat feeds, OpenPhish (phishing) and
   URLhaus (malware), refreshed every 6 hours. This catches the quiet,
   professional-looking phishing pages that contain no scam language at
   all, like fake login and fake recruiter pages. The check is local:
   visited URLs are never sent anywhere.
2b. Look-alike addresses: the visited hostname is compared against the
   allowlist, the known brands, AND the popular-site names in
   data/typo-targets.js, covering character omission, doubling,
   transposition, substitution, hyphen insertion, digit-for-letter
   look-alikes (paypa1, faceb00k, amaz0n) and the omitted dot after www
   (wwwpaypal.com). Measured on 6000 real popular sites, adding the
   popular-name list moved the false-positive rate from 0.23% to 0.40%
   while raising typosquat detection from 15.9% to 78.1%; none of those
   false positives can flag a page on their own, and the high-confidence
   look-alike path produced zero. Re-run test-pages/selftest-node.js
   before changing that list.
3. Heuristic scoring (content/detector.js): the page title and text are
   scored against weighted scam phrase lists (data/scam-phrases.js), a
   toll-free phone number pattern, brand impersonation (brand in the
   page text or in the hostname itself, like secure-chase-login.com),
   typosquatted domains (paypa1.com, wallmart.com - edit distance from
   known reputable names), punycode lookalikes, and cloned sign-in pages
   (real Google/Microsoft login wording plus a credential input on a
   domain that is not the real one). Above a threshold, the page is
   flagged with a plain-language reason. This catches brand-new scam
   pages that no feed knows yet.
4. On-device AI second opinion (experimental): when the heuristics find
   something suspicious but below the flag threshold, Chrome's built-in
   Gemini Nano model (Chrome 138+, if installed) is asked for a verdict.
   It is given the web address and a plain-language, locally-computed
   summary of what is suspicious about that address (look-alike? brand
   name stuffed in? throwaway TLD?), so it can weigh the domain, not just
   the page text. Free, local, private; silently skipped if the model is
   not available. No external reputation service is queried, which would
   mean sending the address off the machine.
   Software-download pages (Softonic-style portals with many "Download"
   buttons, .exe links, installer/keygen language) are ALWAYS routed to the
   AI even at a keyword score of 0, because the danger there is deceptive
   (fake download buttons, bundled adware, cracked-software installers), not
   something keywords can judge. The AI gets extra guidance for that case.
   The AI judges the PAGE only; it is deliberately not allowed to convict an
   individual download button (see below).

## What the "Is this a scam?" button checks

Pressing the button checks the page itself (trusted list, reported-scam feed,
heuristics, then the on-device AI) and then goes one step further: it looks at
where the page's LINKS lead. Plenty of scam pages read as perfectly ordinary
and keep the fraud one click away.

A link raises a warning on two kinds of evidence only:
 - the destination is on the reported-scam feed, or
 - the address is a high-confidence look-alike: a brand mimic
   (paypal.com.evil.net) or a digit-for-letter impostor (paypa1.com).

The ordinary edit-distance typosquat test is deliberately NOT used here, even
though it is used to judge the page's own address. The reason is arithmetic: a
test that is wrong 0.4% of the time is fine once, but a page has dozens of
links, and at eighty links it would raise a false alarm roughly one time in
four. The two signals above matched zero of 6000 real popular sites.

## Fake download buttons on download portals

On a download portal that is not itself a scam, individual "Download" buttons
that are really adverts get switched off in place, greyed out and covered with
a note naming where they actually lead, while the page and the REAL download
keep working. There is a one-click "This was the real download" undo, and an
off switch in the popup.

The rule is deliberately narrow: **a button is only ever switched off on
positive membership in an external, auditable list** - the threat feed, or a
short curated list of decoy networks whose whole business is the deceptive
click. "The destination is on a different domain than the page" is never a
reason to act. That test looks obvious and is catastrophic: because the
scanner runs in every frame, inside an advert frame the advert's own link is
same-domain while the site's genuine CDN link in the main page is
cross-domain, so it spares the advert and greys out the real download. It also
breaks every open-source project that hosts releases elsewhere (LibreOffice,
Notepad++, Firefox), every printer-driver page, and every App Store badge.
Domain comparison appears in exactly one place: deciding that a link is the
site's own, which can only prevent action.

Other guarantees, each asserted in test-pages/neutralizer-selftest.html:
 - Documents and media are out of scope in code, not by scoring. "Download"
   usually means a doctor's forms or a church bulletin, not an installer.
 - The largest download button on the page is never touched. If Guardian is
   going to be wrong, it must not be wrong about the button you came for.
 - At most two buttons per page. A third means our reading of the page is
   wrong (legitimate mirror lists carry dozens), so everything is restored
   and Guardian shows one calm tip instead.
 - No substring matching on class or id: "ad" is the last two letters of
   "downlo-ad", so [class*="ad"] would match the real download's container
   first.
 - Correcting a mistake writes a separate store, never the personal
   allowlist, so fixing an advert mistake cannot switch off scam protection.

What ships on an ordinary ad-funded portal is usually the calm blue tip, not a
badge: most inventory there is ordinary brand advertising, and the site's own
download buttons are first-party. That is the intended outcome. Tuning the
rule down until a badge appears is how false positives get shipped.

Email adds a few checks of its own in Gmail: links are checked against the
blocklist by full URL (so a bad shortener link matches without blocking the
whole shortener), the sender name/domain is checked for brand spoofing, and
a Reply-To that points to a different domain than the sender is flagged when
the message also reads like a scam.

Measured against live data (not our own test cases): on the Tranco top 2,000
legitimate sites the automatic detection wrongly flags 0.3%, and every one is
a recognizable brand-family edge case, not a random site. See TODO.md.

If Guardian ever gets it wrong, the small "This is not a scam" link on the
warning both records the mistake and remembers the site so it stops warning
there.

## Project layout

- manifest.json: extension manifest (Manifest V3)
- background.js: service worker; fires notifications, closes scam tabs,
  keeps stats in chrome.storage.local
- content/detector.js: the scoring engine (pure functions) plus the
  banner builder
- content/page-scan.js: runs on every page, scores it, shows the banner
- content/gmail-scan.js: runs on mail.google.com, scores opened emails
- data/scam-phrases.js: weighted phrase lists by category
- data/allowlist.js: reputable domains that are never flagged
- popup/: the toolbar dashboard
- test-pages/: local demo scam pages for development (see TODO.md for the
  separate blind test suite plan)

## Privacy

- All detection happens inside the browser on this computer
- No data is sent anywhere, ever
- Stats (counts and a short log) are stored locally in chrome.storage.local
