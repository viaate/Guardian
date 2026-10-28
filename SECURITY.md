# Guardian: threat model and known limitations

Written for a security reviewer. It states what Guardian defends against, what
it deliberately does not, where the trust boundaries are, and what is already
known to be weak. Please attack the last section first.

## What this is

A Chrome MV3 extension that warns non-technical older adults about scam
websites and scam emails. Everything runs locally. There is no backend, no
account, and no analytics.

## Who it protects, and from what

The user is assumed to be 65+, not technical, and inclined to trust what a
page tells them. The attacker is assumed to be a commodity phishing or
malware operator: look-alike domains, cloned sign-in pages, fake virus alerts,
fake delivery and prize notices, fake invoices with a phone number, and
deceptive download buttons on ad-funded portals.

## What it explicitly does NOT protect against

Stating these plainly matters, because a user who over-trusts the extension is
worse off than one who does not have it.

- Anything outside the browser: phone calls, text messages, romance scams,
  gift cards bought in a shop. These are the most common frauds against this
  age group and Guardian cannot see any of them.
- Malware already running on the machine.
- A targeted attacker who knows Guardian is installed. The lists are in the
  package and the rules are readable.
- Scam content inside a logged-in webmail other than Gmail.
- Anything on a domain in `data/allowlist.js`. Those are never scanned, which
  is the deliberate price of never crying wolf on a real bank.

## Trust boundaries

- **Leaves the machine:** two HTTP GETs every six hours, to fixed public
  threat-feed URLs (OpenPhish, URLhaus). No visited URL, page content, or
  identifier is ever transmitted, and blocklist checks run against the local
  copy. One optional exception, taken only by explicit click: "Also report it
  to Google" opens Google's report form with the full page address filled in.
  The link says so.
- **Stays on the machine:** every verdict, the personal blocklist, dismissals,
  statistics, and the on-device model's input and output.
- **Untrusted input:** page DOM and text, email content, and the two threat
  feeds. Feed entries are treated as data and filtered through the allowlist
  before storage, so a poisoned feed cannot blocklist a major bank.
- **Isolation:** content scripts run in Chrome's isolated world. Page script
  cannot reach Guardian's functions or storage.

## Permissions and why

| Permission | Why |
|---|---|
| `storage` | Blocklist copy, personal lists, statistics |
| `notifications` | Desktop notification when something is blocked |
| `alarms` | Six-hourly feed refresh |
| `activeTab` | Read the current page when the user presses the button |
| `scripting` | Read the current page when its content script is absent, e.g. a tab open since before install |
| host permissions | The two feed domains only |

Deliberately NOT requested: `tabs` (browsing history), `webRequest`,
`declarativeNetRequest`, `downloads`, `<all_urls>` host permissions.

## Detection tiers

1. **Allowlist** (~600 domains, plus `.gov`/`.mil`/`.edu`). Never flagged.
2. **Reported-scam feeds.** ~2,000 hostnames and ~6,500 exact URLs, refreshed
   six-hourly. Multi-tenant hosts (`raw.githubusercontent.com`, shorteners)
   are matched by full URL, never by hostname. Each feed is cached separately
   with the time it last succeeded, so one feed being unreachable does not
   discard the other's entries.

   A review suggested URLhaus now requires an authentication key. That was
   checked directly against the configured endpoint
   (`urlhaus.abuse.ch/downloads/text_online/`) and it returned 15,962 entries
   unauthenticated, so the finding did not reproduce. The per-feed caching
   above is the mitigation if that changes: protection degrades to the last
   good copy plus the other feed, rather than silently shrinking.
3. **Heuristics.** Weighted scam phrases, brand impersonation, look-alike
   addresses, cloned sign-in pages, insecure password fields. Two thresholds:
   4 raises a calm strip, 6 a full-page warning.
4. **On-device model** (Chrome's Gemini Nano, when present). Never
   load-bearing, and deliberately not permitted to convict an individual
   download button.

## The design rule everything else follows

A false positive is treated as strictly worse than a miss. A warning on a real
bank teaches the user to ignore warnings, which costs more than the scam it
might have caught. Concretely: a control is only ever disabled on positive
membership in an external, auditable list, never on inference. "The destination
is a different domain" is never a reason to act.

Measured against the top 12,000 real popular domains: high-confidence
look-alike detection matched **none of them**, and the full typosquat test
matched 0.40%, none of which can raise a warning on its own.

That is a measurement on one sample, not a guarantee. It says nothing about
sites outside that list, about pages rather than domains, or about how the
rules behave a year from now as the lists drift. Treat "0" as "none in 12,000
tested", which is what it is.

`node test-pages/selftest-node.js` asserts these guarantees and exits non-zero
on regression. `node test-pages/check-refs.js` asserts every function called is
defined in the context that calls it.

## Known weaknesses: please start here

1. **Look-alike domains that redirect immediately.** Content scripts run at
   `document_idle`, so a look-alike whose only job is to bounce the visitor is
   seen at its destination, not at the address the person typed. Blocking it
   earlier was attempted and reverted: stopping the load left the browser free
   to discard the document, producing a blank page.
2. **The download-ad neutralizer modifies live pages.** It is the newest code
   and the least field-tested. It is capped at two controls per page and
   cancels all of them if a third would trigger, but it is the largest
   remaining false-positive surface.
3. **The on-device model is nondeterministic** and absent on most machines, so
   behaviour differs per user and a report may not reproduce.
4. **Warnings are injected after the page loads.** Guardian does not block
   network requests, inspect downloads, or remove anything. A page can act
   before it is judged, and a hostile page may try to cover, imitate or
   intercept the warning. The warning is drawn with the highest possible
   stacking order and its buttons are handled in the capture phase, but this
   is a mitigation, not a guarantee. It is a warning layer, not antivirus.

5. **No telemetry.** If Guardian breaks on a user's machine, nobody learns.
   This is a deliberate privacy trade, and it is also a real operational gap.
6. **Feed staleness.** An entry removed upstream persists locally for up to
   six hours.
7. **Never usability-tested with the target users.** Every number here is
   measured against domain lists, not people. The whole premise is that a
   75-year-old reads the warning and acts on it, and that is untested.
8. **`activeTab` plus `scripting`** lets the popup read the active page when
   the user presses the button. Scoped to user action, but worth confirming.
9. **Content scripts run in all frames**, including third-party ad frames. A
   sub-frame may only escalate to a full-page warning if it holds a credential
   input; that guard is worth attacking.

10. **The scam-awareness exemption is a deliberate, disclosed trade.** A page
    that teaches about a scam quotes the scam's own words and so scores like
    one: a description of the tech-support scam plus the toll-free number the
    article is telling you *not* to ring scored 7 against a threshold of 6, and
    Guardian covered a sheriff's fraud-alert page and a senior centre newsletter
    with "STOP. This is a scam." Those pages are read by exactly the people
    Guardian is for, so `guardianAnalyze` now caps the score below the caution
    threshold when two or more phrases from `GUARDIAN_TEACHING_MARKERS` appear
    (`data/scam-phrases.js`) — wording like "hang up", "Microsoft will never
    call you", "how to spot".

    The cost is an evasion path, and it should be attacked: a scam page could
    plant two of those phrases, invisibly, to hold its own score down. Three
    things bound it. The cap applies **only** when the wording alone convicted
    the page — any look-alike domain, brand mimic, spoofed sender, insecure
    login or credential clone disables it. It cannot touch the threat-feed tier
    at all, which reaches the warning through a separate path and never through
    the score. And the on-device model still reads the page independently.
    Still, on a neutral domain with no address signal, this is a way to be
    quieter than Guardian should be. It was taken because the false positives
    are certain and recurring while the evasion is hypothetical, which is the
    same trade the rest of this document makes.

11. **A first-person account of a scam is still flagged.** A relative's blog
    post — "the screen said her computer was infected, she called, they asked
    for gift cards" — is pure narrative with no advisory wording, so it carries
    none of the markers above and still scores 7. Telling it apart from a scam
    page needs third-person narrative detection ("she called", "my mother"),
    and testimonial-style scam pages use exactly that voice, so the obvious fix
    would cost real detection. Left as a known false positive; the dismissal
    ladder softens it to a calm strip on the second visit.
