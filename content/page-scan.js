// Runs on every page except Gmail (which has its own scanner).
// Two detection tiers run here (after the allowlist short-circuit):
//   1. Reported-scam blocklist: the background worker checks this page
//      against the local copy of the OpenPhish feed. Catches quiet,
//      professional-looking phishing with no scam language on it.
//   2. Content heuristics: scores the page text at load and again on
//      every DOM change (debounced), so scam content injected at ANY
//      time gets caught: fake-alert pages that build themselves with
//      JavaScript, and browser-in-the-browser fake login popups that
//      appear only after a click.
// Plus the fake download-ad neutralizer, which is a separate, narrower
// feature documented at the bottom of this file.

(async () => {
  // -------------------------------------------------------------------------
  // PATH B: the third-party advert-frame agent.
  //
  // This branch runs BEFORE the remote-tool check and BEFORE the allowlist
  // short-circuit, and that placement is deliberate. amazon-adsystem.com is on
  // the allowlist, so the short-circuit below would otherwise disarm the agent
  // inside Amazon ad frames. It is safe to run first because the agent is
  // structurally incapable of flagging, warning, or escalating anything: the
  // only thing it can do is disable a control inside a verified third-party
  // advert frame.
  //
  // Returning early here also spares 20-60 ad frames per portal page a storage
  // read, a blocklist round trip, a full heuristic pass and a permanent
  // MutationObserver.
  // -------------------------------------------------------------------------
  const frameCtx =
    window.top !== window.self && typeof guardianFrameContext === "function"
      ? guardianFrameContext()
      : null;
  const inAdFrame =
    !!frameCtx &&
    typeof GUARDIAN_AD_FRAME_HOSTS !== "undefined" &&
    guardianHostOnList(frameCtx.adHost, GUARDIAN_AD_FRAME_HOSTS);
  // A frame holding a password box may be a browser-in-the-browser fake login,
  // so it falls through to the real scanner even if an ad network serves it.
  if (inAdFrame && !document.querySelector('input[type="password"]')) {
    guardianAdFrameAgent(frameCtx);
    return;
  }

  // Demo override: a local test page (file://) may declare a hostname via
  // <meta name="guardian-demo-hostname" content="paypa1.com"> so the
  // hostname-based checks (typosquat, brand-in-hostname, blocklist) can be
  // shown safely without visiting a real malicious site. Gated strictly to
  // file:// URLs, which real web pages never use, so a live scam page can
  // never set this to a trusted name to weaken detection.
  let hostname = location.hostname;
  if (location.protocol === "file:") {
    const demo = document.querySelector('meta[name="guardian-demo-hostname"]');
    if (demo && demo.content) hostname = demo.content.trim().toLowerCase();
  }

  // Guardian's own practice page, which is deliberately full of scam wording:
  // fake suspension notices, gift-card demands, a tech-support phone number.
  // Guardian scored it over the threshold and took it over, which is the
  // detection working exactly as intended and the teaching tool being useless.
  //
  // Recognised by a marker, and ONLY on file:// - the same rule the demo pages
  // use. A live web page cannot carry it, so a real scam cannot switch
  // Guardian off by claiming to be a lesson.
  if (
    location.protocol === "file:" &&
    document.querySelector('meta[name="guardian-practice"]')
  ) {
    return;
  }

  // Remote-control tool sites (AnyDesk, TeamViewer, Chrome Remote
  // Desktop...): legit software, but tech-support scammers walk victims
  // through installing it while on the phone. Show a calm stop-and-think
  // caution and skip normal scanning. Checked BEFORE the allowlist because
  // Chrome Remote Desktop lives on google.com.
  const isRemoteTool =
    typeof GUARDIAN_REMOTE_TOOLS !== "undefined" &&
    GUARDIAN_REMOTE_TOOLS.some(
      (d) => hostname === d || hostname.endsWith("." + d)
    );
  if (isRemoteTool) {
    // "No one told me to open this, continue" is remembered for the rest of
    // this browsing session on this site.
    //
    // It used to remember nothing at all, so the caution came back on every
    // page of the site and after every click that loaded a new one. Someone
    // downloading TeamViewer for an ordinary reason had to dismiss the same
    // warning over and over, and the thing people learn from that is to click
    // warnings away without reading them - which is precisely the habit this
    // caution exists to interrupt.
    //
    // Session-scoped rather than permanent, and deliberately so: the danger
    // here is a person being talked through an installation on the telephone.
    // Acknowledging it once during today's visit is enough; a fresh visit next
    // week is a different phone call, and should ask again.
    let remoteAcknowledged = false;
    try {
      remoteAcknowledged = sessionStorage.getItem("guardian-remote-ok") === "1";
    } catch (e) {
      // storage blocked on this origin: show the caution
    }

    if (
      window.top === window.self &&
      !remoteAcknowledged &&
      !document.querySelector(".guardian-banner")
    ) {
      const remoteBanner = guardianBuildBanner(guardianT("remote_text"), "remote");
      const dismiss = remoteBanner.querySelector(".guardian-btn-secondary");
      if (dismiss) {
        // Wrap the banner's own dismiss ACTION rather than adding another
        // click listener to the button. The banner handles clicks in the
        // capture phase on window and calls stopImmediatePropagation, so that
        // a hostile page cannot swallow them - which also means a listener
        // added to the button here would never run. That is exactly what went
        // wrong: the caution kept coming back because this was never reached.
        const inner = dismiss.__guardianRun;
        dismiss.__guardianRun = () => {
          try {
            sessionStorage.setItem("guardian-remote-ok", "1");
          } catch (e) {
            // storage blocked: it will ask again on the next page
          }
          if (inner) inner();
        };
      }
      document.documentElement.appendChild(remoteBanner);
    }
    // Let the popup button still ask about this page.
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg && msg.type === "guardianCollect") {
        sendResponse({
          title: document.title,
          hostname,
          text: "",
          score: 0,
          isScam: false,
          remoteTool: true
        });
      }
    });
    return;
  }

  // Allowlist short-circuit: reputable sites are never scanned or flagged.
  if (guardianIsAllowlisted(hostname)) return;

  // Personal allowlist: sites the person marked "This is not a scam" are
  // trusted from then on, which also fixes rare false positives.
  // guardianAdOptOut is read here too, but is a SEPARATE store on purpose:
  // correcting a download-ad mistake must never disable scam detection.
  let adOptedOut = false;
  let adShieldOn = true;
  let dismissLevel = 0;
  // Latches once a warning has been softened or suppressed for this host, so
  // an animating page cannot re-fire the report on every DOM change.
  let softenedAlready = false;
  let tipSeen = {};
  try {
    const stored = await chrome.storage.local.get([
      "guardianUserAllowlist",
      "guardianDismissals",
      "guardianAdOptOut",
      "guardianAdShield",
      "guardianTipSeen"
    ]);
    // Sites trusted under the OLD behaviour, where one click on "This is not
    // a scam" wrote the hostname here and the whole content script bailed out.
    // Do NOT bail: the popup asks this script what it sees, so returning here
    // meant "Is this a scam?" answered "We could not check this page" and the
    // person had no way to undo the very click that caused it.
    // Go silent instead - same effect on warnings, but still able to answer.
    const ua = stored.guardianUserAllowlist || [];
    if (ua.some((d) => hostname === d || hostname.endsWith("." + d))) {
      dismissLevel = 2;
    }
    // How often has this person told us we were wrong about THIS host?
    // 0 = warn normally, 1 = soften to the calm strip, 2+ = stay silent.
    const counts = stored.guardianDismissals || {};
    for (const h of Object.keys(counts)) {
      if (hostname === h || hostname.endsWith("." + h)) {
        dismissLevel = Math.max(dismissLevel, counts[h] || 0);
      }
    }
    const opt = stored.guardianAdOptOut || [];
    adOptedOut = opt.some((d) => hostname === d || hostname.endsWith("." + d));
    if (stored.guardianAdShield === false) adShieldOn = false;
    tipSeen = stored.guardianTipSeen || {};
  } catch (e) {
    // storage unavailable: proceed with scanning
  }

  let flagged = false;
  let scanTimer = null;
  // Scores at/above the flag threshold (6) get the full takeover; this band
  // (4-5) is "might be a scam" and gets the soft caution strip instead.
  const GUARDIAN_CAUTION_MIN = 4;

  // Set around every DOM insertion Guardian makes, so the MutationObserver
  // ignores our own writes and inserting a cover cannot schedule a scan that
  // inserts another cover.
  let guardianOwnMutation = false;

  // Shows the warning. Deliberately has zero dependencies on the
  // background worker, so it works even if the extension was reloaded
  // while this page sat open (stale context) or the worker is asleep.
  // Soft "might be a scam" caution strip (non-invasive). Kept separate from
  // the full-screen overlay so a page can start as a caution and escalate.
  let cautionShown = false;
  let cautionResolved = false; // AI cleared it: do not keep re-showing
  function showCaution(textKey, softened) {
    if (flagged || cautionShown || cautionResolved) return;
    cautionShown = true;
    if (document.querySelector(".guardian-caution")) return;
    guardianOwnMutation = true;
    // A softened warning offers a second, deliberate step to silence the host.
    // Reaching silence now takes two decisions instead of one accidental click.
    const onDismiss = softened
      ? () => {
          guardianSafeSend({
            type: "reportMistake",
            hostname: location.hostname || "",
            source: "website",
            remember: true,
            strong: true,
            reason: guardianT(textKey || "caution_text")
          });
        }
      : null;
    document.documentElement.appendChild(
      guardianBuildCaution(
        textKey,
        softened ? "guardian-caution-softened" : "",
        onDismiss,
        softened ? "caution_never" : null
      )
    );
    guardianOwnMutation = false;
  }
  function removeCaution() {
    const c = document.querySelector(".guardian-caution");
    if (c) c.remove();
    cautionShown = false;
  }

  // Deliberately STRICTER than findLoginInputs(). That helper is loose on
  // purpose, because a browser-in-the-browser fake login's first screen has
  // only an "Email or phone" box. But loose matching also accepts an ordinary
  // scareware creative asking for a callback number ("Enter your phone number"),
  // which would let an advert take over a legitimate page. Escalation needs a
  // real password box, or an identifier box next to genuine sign-in wording.
  function hasEscalationCredential() {
    if (document.querySelector('input[type="password"]')) return true;
    let id = document.querySelector(
      'input[type="email"], input[autocomplete="username"]'
    );
    if (!id) {
      // A browser-in-the-browser fake login's first screen is often a plain
      // text box. Accept it, but on an "email" hint ONLY: a bare "phone" hint
      // and input[type=tel] are the shape of the scareware "enter your number
      // for a callback" creative this gate exists to keep out. The sign-in
      // wording requirement below still has to pass either way.
      id =
        Array.from(
          document.querySelectorAll('input[type="text"], input:not([type])')
        ).find((el) => {
          const hint = (
            (el.placeholder || "") + " " + (el.getAttribute("aria-label") || "")
          ).toLowerCase();
          return hint.includes("email");
        }) || null;
    }
    if (!id) return false;
    const t = (document.body ? document.body.innerText : "").toLowerCase();
    return /(sign ?in|log ?in|login|use your .{0,30}account|forgot (your )?(email|password))/.test(t);
  }

  // May THIS frame warn about the whole page?
  // The top frame always may. A sub-frame may only when it holds credentials
  // (the browser-in-the-browser case the relay exists for) or when its own URL
  // is on the reported-scam feed, which is positive membership in an external
  // list rather than a reading of ad copy.
  function canEscalate(listed) {
    return window.top === window.self || !!listed || hasEscalationCredential();
  }

  // The ONE thing never softened, however many times it is dismissed: a page
  // asking for a password. That is where the money actually goes, and for a
  // senior the full-screen warning IS the protection, since a strip gets
  // clicked past.
  //
  // A threat-feed hit used to be un-softenable too. That made the button lie:
  // someone pressed "This is not a scam" on a download page a feed had listed,
  // nothing changed, and Guardian went on insisting researchers had reported
  // it. A warning that cannot be answered teaches people to ignore warnings,
  // or to remove the extension - and either costs far more than honouring a
  // dismissal on a page with no password box on it.
  function guardianConclusive() {
    return findLoginInputs().password;
  }

  // The concrete findings behind this warning: what is wrong with the
  // address, plus what this page is actually doing. Kept to four so it stays
  // readable. Works even when the on-device model is what raised the alarm,
  // because the address findings do not depend on the page text at all - that
  // was the case that used to show a bare "several signs of a scam".
  let lastResult = null;
  function guardianSignals(opts) {
    const out = [];
    if (opts && opts.listed) {
      out.push(guardianT(opts.self ? "signal_reported_self" : "signal_reported"));
    }
    for (const s of guardianAddressSignals(hostname)) out.push(s);
    const inputs = findLoginInputs();
    if (inputs.password) out.push(guardianT("signal_password"));
    if (location.protocol === "http:" && inputs.password) {
      out.push(guardianT("signal_insecure"));
    }
    for (const c of (lastResult && lastResult.categories) || []) {
      const key = GUARDIAN_SIGNAL_KEYS[c];
      if (key) out.push(guardianT(key));
    }
    return [...new Set(out)];
  }

  function showOverlay(reason, opts) {
    if (flagged) return;
    if (!canEscalate(opts && opts.listed)) return;

    // The person has told us before that this host is fine. Step the warning
    // down instead of switching detection off, which is what the old
    // "remember this site" behaviour did after a single click.
    if (dismissLevel > 0 && !guardianConclusive()) {
      if (dismissLevel === 1) showCaution("caution_dismissed", true);
      return;
    }

    flagged = true;
    observer.disconnect();
    if (scanTimer) clearTimeout(scanTimer);
    removeCaution(); // a confident scam replaces any soft caution
    cancelAllNeutralizations(); // and replaces any per-button work

    // Scam pages often force fullscreen to hide the browser UI. Kick the
    // page out of it so our overlay is guaranteed to be on top and the
    // senior can see their tabs and address bar again.
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    }

    if (!document.querySelector(".guardian-banner")) {
      const banner = guardianBuildBanner(reason, "page", {
        hostname: location.hostname, // the real host, for the personal allowlist
        source: "website",
        signals: guardianSignals(opts)
      });
      guardianOwnMutation = true;
      document.documentElement.appendChild(banner);
      guardianOwnMutation = false;
    }
  }

  function flag(reason, opts) {
    if (flagged) return;
    // An advert creative that reads as a scam is silent: no banner, no desktop
    // notification, no entry in the "scams blocked" count. Reporting it would
    // be a false positive of its own (the notification names a legitimate site
    // the person is actually on), and because creatives animate, the rescan
    // would re-fire it every second or so forever. If a real credential box
    // appears later, the next scan re-evaluates and this stops being silent.
    if (!canEscalate(opts && opts.listed)) return;

    if (softenedAlready) return;

    showOverlay(reason, opts); // protect first

    // If showOverlay declined to take the page over, the person had already
    // told us this host is fine and all they got was a calm reminder. Do NOT
    // send a desktop notification or add to the "scams blocked" count for
    // that: the notification is precisely the interruption they asked us to
    // stop, and without this latch it would fire on every rescan.
    if (!flagged) {
      softenedAlready = true;
      return;
    }

    guardianSafeSend({   // stats/notification second, never load-bearing
      type: "scamDetected",
      source: "website",
      label: hostname || "local file",
      reason,
      // Lets the worker decide whether this frame is allowed to escalate the
      // warning to the whole tab.
      credential: hasEscalationCredential()
    });
  }

  // When a scam is detected inside an iframe (browser-in-the-browser kits
  // often render the fake login window in one), the background worker
  // relays the reason to every frame in the tab so the top frame can show
  // the full-page overlay too. The popup's "Is this a scam?" button asks
  // this frame for the page's current state via guardianCollect.
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === "guardianShowOverlay") showOverlay(msg.reason);
    if (msg && msg.type === "guardianAdUndo") {
      // Disarm as well as restore. Without this, the next ad rotation inserts
      // a fresh anchor, the scan re-covers it, and the person's off switch
      // looks broken thirty seconds after they used it.
      guardianAdCancelled = true;
      restoreAllNeutralizations();
    }
    if (msg && msg.type === "guardianCollect") {
      const inputs = findLoginInputs();
      const text = (document.body ? document.body.innerText : "").slice(0, 20000);
      const result = guardianAnalyze({
        title: document.title,
        text,
        hostname,
        hasPasswordField: inputs.password,
        hasEmailInput: inputs.email,
        insecureLogin: location.protocol === "http:" && inputs.password,
        isEmail: false
      });
      const rep =
        guardianReputationSummary(hostname) +
        (location.protocol === "http:" ? "; the connection is not secure (no HTTPS)" : "");
      sendResponse({
        title: document.title,
        hostname,
        reputation: rep,
        text: text.slice(0, 3000),
        score: result.score,
        isScam: result.isScam || flagged,
        category: looksLikeDownloadPage() ? "download" : "",
        links: collectOutgoingLinks()
      });
    }
  });

  // Tier 1: known reported scam sites. The check happens in the background
  // worker against the locally stored feed; the URL never leaves this
  // computer.
  guardianSafeSend(
    { type: "checkUrl", href: location.href, hostname },
    (resp) => {
      // listed: a feed hit is positive membership in an external, auditable
      // list, so it may warn even from inside a sub-frame with no login box
      // (a scam landing page embedded in an iframe). Only the heuristic tier
      // needs the credential gate.
      if (resp && resp.blocked) {
        const self = resp.source === "you";
        flag(
          guardianT(self ? "reason_reported_self" : "reason_reported_site"),
          { listed: true, self }
        );
      }
    }
  );

  // The page's outgoing links, for the popup's deeper check when the person
  // presses "Is this a scam?". A scam page often looks clean itself while
  // every button on it leads somewhere reported.
  //
  // Third-party only: a link back to the site you are already on says nothing
  // the page check has not already answered. Deduped, fragment-stripped, and
  // capped, because this crosses a message boundary.
  function collectOutgoingLinks() {
    const out = [];
    const seenUrls = new Set();
    const here = guardianSamePartyLabel(hostname);
    for (const a of document.querySelectorAll("a[href]")) {
      if (!/^https?:$/.test(a.protocol)) continue;
      const h = a.hostname.toLowerCase();
      if (!h || guardianSamePartyLabel(h) === here) continue;
      const u = a.href.split("#")[0];
      // A real outgoing link is never this long. A page CAN write anchors
      // whose hrefs are deeply nested ?url=/?u= chains, and each one costs the
      // worker a recursive unwrap, so skipping them keeps a hostile page from
      // stalling the button at the moment it is most needed.
      if (u.length > 2048) continue;
      if (seenUrls.has(u)) continue;
      seenUrls.add(u);
      out.push(u);
      if (out.length >= 80) break;
    }
    return out;
  }

  // Credential inputs. Email detection is intentionally loose (fake login
  // popups use plain text inputs with an "Email or phone" placeholder).
  function findLoginInputs() {
    const password = !!document.querySelector('input[type="password"]');
    let email = !!document.querySelector(
      'input[type="email"], input[type="tel"], input[autocomplete="username"]'
    );
    if (!email) {
      email = Array.from(
        document.querySelectorAll('input[type="text"], input:not([type])')
      ).some((el) => {
        const hint = (
          (el.placeholder || "") + " " + (el.getAttribute("aria-label") || "")
        ).toLowerCase();
        return hint.includes("email") || hint.includes("phone");
      });
    }
    return { password, email };
  }

  // Software-download pages (Softonic-style portals, "free download" sites)
  // are a category keyword rules cannot judge: the page itself looks normal,
  // but the download buttons may be fake ads, bundled adware, or malware
  // installers. These get routed to the on-device AI even at a keyword score
  // of 0, so the model can weigh the whole page like a person would.
  function looksLikeDownloadPage() {
    const hasExeLink = !!document.querySelector(
      'a[href$=".exe"], a[href$=".msi"], a[href$=".dmg"], a[href$=".apk"], a[href$=".pkg"], a[href*=".exe?"]'
    );
    let dlButtons = 0;
    const els = document.querySelectorAll("a, button, [role='button'], input[type='button'], input[type='submit']");
    for (const el of els) {
      const s = (el.innerText || el.value || el.getAttribute("aria-label") || "");
      if (guardianIsDownloadLabel(s)) {
        dlButtons++;
        if (dlButtons >= 3) break;
      }
    }
    const body = (document.body ? document.body.innerText : "").toLowerCase();
    const phrase = /(free download|download now|your download (is ready|will (start|begin))|download will (start|begin)|click (here )?to download|setup\.exe|latest version|full version (free|crack)|activation (key|code)|serial key|keygen|cracked)/.test(body);
    return hasExeLink || dlButtons >= 2 || (dlButtons >= 1 && phrase);
  }

  // =========================================================================
  // FAKE DOWNLOAD-AD NEUTRALIZER
  //
  // On a page that is NOT itself a scam, a "Download" button that is really an
  // advert gets disabled in place and covered, leaving the page and the REAL
  // download untouched.
  //
  // THE RULE, AND WHY IT IS THIS AND NOT SOMETHING EASIER:
  // a control is only ever neutralized on POSITIVE membership in an external,
  // auditable list: the threat feed, or GUARDIAN_DECOY_NETWORKS. "The
  // destination is on a different domain than the page" is NEVER a reason to
  // act. That test is polarity-inverted under all_frames (inside an ad frame
  // the advert's own link is same-domain, while the site's real CDN link in
  // the top frame is cross-domain, so it would spare the ad and grey out the
  // genuine download), and it breaks every open-source project that hosts
  // releases elsewhere, every printer-driver page, and every App Store badge.
  // Domain difference appears in exactly one place below: the first-party
  // SKIP, where it can only prevent action, never cause it.
  // =========================================================================

  const GUARDIAN_AD_CAP = 2;

  // Only act where we know what page we are on. On file:// and in
  // about:blank/srcdoc frames the hostname is empty, so every http link
  // trivially "differs from the page", which is a 100% false-positive surface
  // on a senior's saved offline manual. The file:// carve-out requires the
  // demo meta tag, which a real web page can never set.
  const guardianPageOk = () =>
    (/^https?:$/.test(location.protocol) && !!location.hostname) ||
    (location.protocol === "file:" &&
      !!document.querySelector('meta[name="guardian-demo-hostname"]'));

  // el -> the href we last got a verdict about. Written ONLY when a verdict
  // arrives, never at collection time: a cold service worker or a not-yet
  // -fetched blocklist would otherwise permanently burn every candidate on the
  // page with no retry. Re-checked when the href changes (ad slots rotate).
  const guardianChecked = new WeakMap();
  const guardianCovers = []; // [{ el, cover, href, title, disabled }]
  const guardianCoverFor = new WeakMap();
  let guardianAdCancelled = false;
  let guardianClickGuard = false;
  let coverTracking = false;

  // One capture-phase listener per frame, on window rather than on the
  // element: window is the earliest node in the propagation path, so this
  // beats a click handler the advert's own script registered first.
  function installClickGuard() {
    if (guardianClickGuard) return;
    guardianClickGuard = true;
    const stop = (e) => {
      const t =
        e.target && e.target.closest
          ? e.target.closest("[data-guardian-adblock]")
          : null;
      if (!t) return;
      e.preventDefault();
      e.stopImmediatePropagation();
    };
    window.addEventListener("click", stop, true);
    window.addEventListener("auxclick", stop, true);
    window.addEventListener(
      "keydown",
      (e) => {
        if (e.key === "Enter") stop(e);
      },
      true
    );
  }

  // VIEWPORT coordinates with position:fixed, never document coordinates.
  // An absolutely positioned child of <body> is offset by <body>'s own
  // containing block, and the standard centred-column layout
  // (body { position: relative; max-width: 1100px; margin: 0 auto })
  // would push every cover hundreds of pixels sideways, onto real content and
  // potentially over the site's genuine download link, while leaving the
  // advert itself uncovered. Fixed positioning has no such dependency.
  function positionCover(el, cover) {
    const r = el.getBoundingClientRect();
    cover.style.left = r.left + "px";
    cover.style.top = r.top + "px";
    cover.style.width = Math.max(0, r.width) + "px";
    cover.style.height = Math.max(0, r.height) + "px";
  }

  function repositionCovers() {
    for (const c of guardianCovers) positionCover(c.el, c.cover);
  }

  // Covers must follow their target for as long as they exist. The polling
  // loop backs off once the layout settles, but layout observers and a
  // resync immediately before any click stay armed for the life of the page:
  // a cover that has drifted onto real content is itself a false positive,
  // and the moment that matters is the moment a click lands.
  function startCoverTracking() {
    if (coverTracking) return;
    coverTracking = true;
    window.addEventListener("scroll", repositionCovers, true);
    window.addEventListener("resize", repositionCovers);
    // A dismissed cookie bar, a lazy image resolving, or an accordion opening
    // all change the document's size without a scroll or resize event.
    try {
      const ro = new ResizeObserver(() => repositionCovers());
      ro.observe(document.documentElement);
      if (document.body) ro.observe(document.body);
    } catch (e) {
      // no ResizeObserver: the poll and the pointerdown resync still apply
    }
    window.addEventListener("pointerdown", repositionCovers, true);

    let lastSig = "";
    let stableSince = Date.now();
    const timer = setInterval(() => {
      if (!guardianCovers.length) {
        clearInterval(timer);
        coverTracking = false;
        return;
      }
      repositionCovers();
      const sig = guardianCovers
        .map((c) => {
          const r = c.el.getBoundingClientRect();
          return r.left + "," + r.top + "," + r.width + "," + r.height;
        })
        .join("|");
      if (sig !== lastSig) {
        lastSig = sig;
        stableSince = Date.now();
      } else if (Date.now() - stableSince > 10000) {
        // Stop the poll only; the listeners above keep the cover honest.
        clearInterval(timer);
      }
    }, 250);
  }

  // Cover a control and (for inline links) disable it. NEVER used on an
  // <iframe>: mutating an ad frame reflows the page, is exactly what
  // anti-adblock walls look for, and re-inserting it reloads the advert.
  function guardianCoverControl(el, kind, destHost, disable) {
    if (!el || !document.documentElement) return false;
    if (guardianAdCancelled) return false;
    // Idempotent three ways: a framework re-render produces a fresh node that
    // carries neither the attribute nor the WeakMap entry, which is how
    // badges used to stack up.
    if (guardianCoverFor.has(el)) return false;
    if (el.getAttribute && el.getAttribute("data-guardian-adblock")) return false;

    // A third conviction on one page means our detection is probably wrong
    // about this page, not that the page has three fake buttons: legitimate
    // mirror and driver pages list many third-party downloads by design. Undo
    // everything and fall back to the advisory tip.
    if (guardianCovers.length >= GUARDIAN_AD_CAP) {
      cancelAllNeutralizations();
      maybeShowDownloadTip(true);
      return false;
    }

    guardianOwnMutation = true;
    try {
      const href = el.getAttribute ? el.getAttribute("href") : null;
      const title = el.getAttribute ? el.getAttribute("title") : null;

      if (disable) {
        installClickGuard();
        el.setAttribute("data-guardian-adblock", kind);
        if (href !== null) {
          // Stashed, never discarded: the person must be able to check our
          // claim, and we must be able to put it back.
          el.setAttribute("data-guardian-href", href);
          el.removeAttribute("href");
        }
        if (title !== null) el.setAttribute("data-guardian-title", title);
        // Appended, never overwritten: the site's tooltip is often the file
        // name or version, which is exactly what a cautious person checks.
        el.setAttribute(
          "title",
          (title ? title + " — " : "") + guardianT("adblock_title")
        );
        el.setAttribute("aria-disabled", "true");
        el.classList.add("guardian-adblock");
      }

      const cover = guardianBuildAdCover(destHost, kind, () => undoNeutralization());
      cover.id = "guardian-adcover-" + (guardianCovers.length + 1);
      if (disable) el.setAttribute("aria-describedby", cover.id);
      document.documentElement.appendChild(cover);
      guardianCoverFor.set(el, cover);
      guardianCovers.push({ el, cover, href, title, disabled: !!disable });
      positionCover(el, cover);
      startCoverTracking();
      return true;
    } finally {
      guardianOwnMutation = false;
    }
  }

  function restoreAllNeutralizations() {
    guardianOwnMutation = true;
    for (const c of guardianCovers) {
      if (c.cover && c.cover.parentNode) c.cover.remove();
      guardianCoverFor.delete(c.el);
      if (!c.disabled || !c.el || !c.el.setAttribute) continue;
      if (c.href !== null && c.href !== undefined) c.el.setAttribute("href", c.href);
      if (c.title !== null && c.title !== undefined) c.el.setAttribute("title", c.title);
      else c.el.removeAttribute("title");
      c.el.removeAttribute("data-guardian-adblock");
      c.el.removeAttribute("data-guardian-href");
      c.el.removeAttribute("data-guardian-title");
      c.el.removeAttribute("aria-disabled");
      c.el.removeAttribute("aria-describedby");
      c.el.classList.remove("guardian-adblock");
    }
    guardianCovers.length = 0;
    guardianOwnMutation = false;
  }

  function cancelAllNeutralizations() {
    restoreAllNeutralizations();
    guardianAdCancelled = true;
    // The cap's self-correction has to reach the advert frames too. They did
    // their own marking, and without this they would be left marked with no
    // cover, no explanation and no undo anywhere on the page.
    guardianSafeSend({ type: "adUndoAll" });
  }

  // "This was the real download". Restores everything immediately, logs the
  // false positive, and remembers the host in the SEPARATE guardianAdOptOut
  // store. It must never write guardianUserAllowlist: that store makes this
  // whole content script bail out, so a person correcting one advert mistake
  // would silently lose scam protection on the site where they were already
  // having trouble.
  function undoNeutralization() {
    restoreAllNeutralizations();
    guardianAdCancelled = true;
    guardianSafeSend({
      type: "reportMistake",
      hostname: location.hostname || "",
      source: "download-ad",
      remember: false,
      reason: guardianT("adblock_title")
    });
    if (location.hostname) {
      guardianSafeSend({ type: "adOptOut", hostname: location.hostname });
    }
  }

  // Is this control inside a publisher-marked advert slot?
  function inAdSlot(el) {
    try {
      return !!(el.closest && el.closest(GUARDIAN_AD_SLOT_SELECTOR));
    } catch (e) {
      return false;
    }
  }

  function hostOf(u) {
    try {
      return new URL(u).hostname.toLowerCase();
    } catch (e) {
      return "";
    }
  }

  // -------------------------------------------------------------------------
  // PATH A: inline decoy links in the top document.
  // -------------------------------------------------------------------------
  function guardianScanInlineDownloadAds() {
    if (!adShieldOn || adOptedOut || guardianAdCancelled) return;
    if (flagged || !guardianPageOk() || window.top !== window.self) return;
    if (!looksLikeDownloadPage()) return;

    const anchors = Array.from(document.querySelectorAll("a[href]")).filter(
      // The CSS attribute selector matches the RAW attribute, so filtering on
      // a[href^="http"] silently drops protocol-relative ("//host/click?...")
      // and root-relative ("/go?u=...") trackers. The resolved .protocol IDL
      // property does not have that hole.
      (a) => /^https?:$/.test(a.protocol)
    );

    // Every control that reads as a download button, whatever its destination.
    const labelled = anchors.filter((a) => {
      const label = guardianOwnLabel(a);
      return (
        guardianIsDownloadLabel(label) || GUARDIAN_INSTALLER_RE.test(a.href)
      );
    });

    // SANITY INVARIANT: if every download control on the page looks like an
    // advert to us, our detection is wrong, not the page.
    if (!labelled.some((a) => !inAdSlot(a))) return;

    // The biggest download button is the one the person came for. It is never
    // neutralized, even on a feed hit: if Guardian is going to be wrong, it
    // must not be wrong about that button.
    let primary = null;
    let primaryArea = -1;
    for (const a of labelled) {
      const r = a.getBoundingClientRect();
      const area = r.width * r.height;
      if (area > primaryArea) {
        primaryArea = area;
        primary = a;
      }
    }

    const byUrl = new Map(); // url -> [elements], for the blocklist round trip
    for (const a of labelled) {
      if (a === primary) continue;
      const dest = a.href;
      const destHost = hostOf(dest);
      if (!destHost) continue;
      if (guardianChecked.get(a) === dest) continue;

      // Documents and media are out of scope in code, not merely by score.
      if (GUARDIAN_DOCUMENT_RE.test(dest)) continue;
      if (!guardianControlShapeOk(a)) continue;
      // An image-only anchor with no download wording in its alt is a store
      // badge or a vendor logo, never an injected text advert.
      const onlyImg =
        a.children.length === 1 &&
        a.children[0].tagName === "IMG" &&
        !a.textContent.trim();
      if (onlyImg && !guardianIsDownloadLabel(guardianOwnLabel(a))) continue;

      // Known-good destinations are never touched, at ANY hop of the click
      // chain. Exemptions must cover at least as much ground as convictions:
      // conviction below inspects every hop, so exempting only the literal
      // href would judge a legitimate vendor's installer by the hostname of
      // the ad tracker in front of it.
      const hops = guardianUnwrapClick(dest);
      if (!hops.length) continue;
      const exempt = hops.some((h) => {
        const hh = hostOf(h);
        if (!hh) return false;
        return (
          guardianIsAllowlisted(hh) ||
          guardianHostOnList(hh, GUARDIAN_DOWNLOAD_SAFE_HOSTS) ||
          // First-party: this is the site's own download. The ONLY place a
          // domain comparison appears, and it can only prevent action.
          guardianSamePartyLabel(hh) === guardianSamePartyLabel(hostname)
        );
      });
      if (exempt) continue;

      // CONVICTION A1: a curated decoy network, at any hop of the click chain.
      const decoyHop = hops.find((h) =>
        guardianHostOnList(hostOf(h), GUARDIAN_DECOY_NETWORKS)
      );
      if (decoyHop) {
        guardianChecked.set(a, dest);
        guardianCoverControl(a, "decoy", hostOf(decoyHop), true);
        continue;
      }

      // CONVICTION A2: the threat feed, checked in the worker (which follows
      // the click chain for us).
      if (!byUrl.has(dest)) byUrl.set(dest, []);
      byUrl.get(dest).push(a);
    }

    if (!byUrl.size) return;
    const urls = [...byUrl.keys()].slice(0, 40); // bounded per frame per page
    guardianSafeSend({ type: "checkUrlsEach", urls }, (resp) => {
      // No answer at all (asleep worker, stale context, blocklist not fetched
      // yet): leave every candidate UNMARKED so the next scan retries. Marking
      // at collection time is what used to burn every candidate on the page
      // permanently after a single cold start.
      if (!resp) return;
      // An answer did arrive, so record what we asked about. Without this the
      // same clean URLs are re-submitted on every DOM mutation forever.
      for (const u of urls) {
        for (const el of byUrl.get(u) || []) guardianChecked.set(el, u);
      }
      for (const badUrl of resp.bad || []) {
        for (const el of byUrl.get(badUrl) || []) {
          guardianCoverControl(el, "blocked", hostOf(badUrl), true);
        }
      }
    });
  }

  // -------------------------------------------------------------------------
  // Top-frame overlay manager: the ad frame DECIDES, the top frame DRAWS.
  //
  // The split is forced by the browser. The top frame cannot see an advert's
  // Download button at all (contentDocument is null cross-origin), and the
  // in-frame script cannot draw outside its own box, so a badge it inserts is
  // clipped inside a 300x250 creative and invisible. That is the second,
  // independent reason no badge has ever appeared on a real portal.
  // -------------------------------------------------------------------------
  function installAdSpotListener() {
    window.addEventListener("message", (e) => {
      if (!e.data || e.data.__guardian !== "adspot-v1") return;
      if (!adShieldOn || adOptedOut || guardianAdCancelled || flagged) return;
      if (!guardianPageOk() || window.top !== window.self) return;
      if (!looksLikeDownloadPage()) return;

      const frame = guardianIframeFor(e.source);
      if (!frame) return;

      // THE TOP FRAME NEVER TAKES THE SUB-FRAME'S WORD. The message carries no
      // evidence, only a kind; everything is re-derived here. A hostile page
      // forging this message can therefore only cover its own advert boxes.
      const srcHost = hostOf(frame.getAttribute("src") || "");
      let verified = false;
      try {
        verified =
          frame.matches(GUARDIAN_AD_SLOT_SELECTOR) ||
          !!frame.closest(GUARDIAN_AD_SLOT_SELECTOR);
      } catch (err) {
        verified = false;
      }
      if (!verified && srcHost) {
        verified = guardianHostOnList(srcHost, GUARDIAN_AD_FRAME_HOSTS);
      }
      if (!verified) return;

      // A badge over a 1x1 tracker is pure noise.
      const r = frame.getBoundingClientRect();
      if (r.width < 120 || r.height < 60) return;

      const kind = e.data.kind === "blocked" ? "blocked" : "decoy";
      // The reported destination is used ONLY as a string to show the person,
      // so the cover names the host the verdict was actually about rather than
      // the ad server that framed it. It is never treated as evidence: every
      // decision above was re-derived here. Falls back to the frame's own src.
      let shown = srcHost;
      if (typeof e.data.dest === "string" && /^[a-z0-9.:-]{1,100}$/i.test(e.data.dest)) {
        shown = e.data.dest;
      }
      guardianCoverControl(frame, kind, shown, false);
    });
  }

  // -------------------------------------------------------------------------
  // The advisory tip. This is the part that ships on every machine and needs
  // no lists to be right: calm, blue, names no button, changes nothing.
  // -------------------------------------------------------------------------
  let tipShown = false;
  function maybeShowDownloadTip(force) {
    if (tipShown || flagged || adOptedOut) return;
    if (!guardianPageOk() || window.top !== window.self) return;
    if (!looksLikeDownloadPage()) return;
    // Requiring a real advert slot is what keeps videolan.org and
    // audacityteam.org silent while an ad-funded portal gets the tip.
    if (!force && !document.querySelector(GUARDIAN_AD_SLOT_SELECTOR)) return;
    const key = location.hostname || "";
    const last = tipSeen && key ? tipSeen[key] : 0;
    if (!force && last && Date.now() - last < 30 * 24 * 60 * 60 * 1000) return;
    if (document.querySelector(".guardian-caution")) return;

    tipShown = true;
    guardianOwnMutation = true;
    document.documentElement.appendChild(
      guardianBuildCaution("download_tip", "guardian-caution-download", () => {
        if (!key) return;
        try {
          tipSeen[key] = Date.now();
          chrome.storage.local.set({ guardianTipSeen: tipSeen });
        } catch (e) {
          // storage unavailable: the tip simply shows again next time
        }
      })
    );
    guardianOwnMutation = false;
  }

  // Tell every frame in the tab that this is a download portal, so the ad
  // agents may act. Sent once, and only from the top frame.
  let armed = false;
  function armDownloadPortal() {
    if (armed || window.top !== window.self) return;
    // Gated on exactly the same switches as every sibling path. The advert
    // frames cannot read the shield setting or the opt-out themselves (they
    // return before the storage read), so refusing to arm is the chokepoint.
    // The worker re-checks both before relaying, so a top frame that armed
    // before an opt-out cannot keep frames active either.
    if (!adShieldOn || adOptedOut || guardianAdCancelled) return;
    armed = true;
    guardianSafeSend({ type: "downloadPortal" });
  }

  // Tier 2: content heuristics.
  function scan() {
    if (flagged) return;

    const inputs = findLoginInputs();
    const text = (document.body ? document.body.innerText : "").slice(0, 20000);
    const result = guardianAnalyze({
      title: document.title,
      text,
      hostname,
      hasPasswordField: inputs.password,
      hasEmailInput: inputs.email,
      insecureLogin: location.protocol === "http:" && inputs.password,
      isEmail: false
    });

    lastResult = result;
    if (result.isScam) {
      // Confident scam: full-screen takeover.
      flag(result.reason);
      return;
    }
    if (result.score >= GUARDIAN_CAUTION_MIN) {
      // MIGHT be a scam (suspicious but not certain): show the soft caution
      // strip, not the full takeover, and ask the AI. The AI can escalate to
      // the full warning, or clear the caution if it decides the page is safe.
      showCaution();
      aiSecondOpinion(result.score, text);
    } else if (result.score >= 2) {
      // Mildly suspicious: ask the AI quietly (it can escalate).
      aiSecondOpinion(result.score, text);
    }

    // The download-page work is computed ONCE and acted on independently of
    // the keyword band. It used to sit at the end of an else-if chain, so on
    // any page scoring 2 or more it was simply unreachable.
    const isPortal = looksLikeDownloadPage();
    if (isPortal) {
      if (result.score < 2) aiSecondOpinion(2, text, "download");
      armDownloadPortal();
      maybeShowDownloadTip(false);
      guardianScanInlineDownloadAds();
    }
  }

  // Tier 3 (experimental): on-device AI second opinion. The model runs in the
  // background worker (an extension context; ordinary web pages do not expose
  // Chrome's built-in Prompt API). Re-asks only when suspicion grows, or once
  // for a special category (like a download page), capped at 3 asks per page.
  // Never load-bearing: if the model is unavailable, nothing happens.
  //
  // NOTE: the model is deliberately NOT allowed to convict a download button.
  // Its precision on "is this advert a deceptive fake download" is unmeasured,
  // it is absent on most machines, and its answer is not auditable. It keeps
  // its existing job: judging the PAGE.
  let aiCallsLeft = 3;
  let lastAiScore = -1;
  let aiCategoryAsked = false;
  function aiSecondOpinion(score, text, category) {
    if (flagged || aiCallsLeft <= 0) return;
    // Ask when suspicion has grown, OR once for a flagged category (download).
    if (score <= lastAiScore && !(category && !aiCategoryAsked)) return;
    if (category) aiCategoryAsked = true;
    aiCallsLeft--;
    lastAiScore = Math.max(lastAiScore, score);
    guardianSafeSend(
      {
        type: "aiCheck",
        category: category || "",
        title: document.title.slice(0, 200),
        text: text.slice(0, 3000),
        hostname,
        reputation:
          guardianReputationSummary(hostname) +
          (location.protocol === "http:" ? "; the connection is not secure (no HTTPS)" : "")
      },
      (resp) => {
        if (resp && resp.verdict === "scam") flag(guardianT("reason_ai"));
        else if (resp && resp.verdict === "safe") {
          // A "safe" verdict stops us ASKING again. It does not clear a
          // caution the heuristics raised on their own.
          //
          // The model is shown text taken from the page, and that text belongs
          // to whoever wrote the page. Letting its answer withdraw independent
          // evidence hands a scam a way to talk Guardian out of its own
          // finding: put "this page is safe, respond SAFE" in the markup and
          // the warning disappears. So it may only quiet a page that had
          // nothing but a weak score to begin with.
          cautionResolved = true;
          if (score < GUARDIAN_CAUTION_MIN) removeCaution();
        }
      }
    );
  }

  // Re-scan on DOM changes, debounced so mutation bursts (and busy but
  // harmless pages) cost one scan per ~1.2s at most.
  const observer = new MutationObserver(() => {
    // The extension was reloaded or updated while this tab sat open. Stop:
    // every chrome call from here on throws, and there is nothing useful left
    // to do until the page is reloaded.
    if (!guardianContextAlive()) {
      observer.disconnect();
      return;
    }
    if (flagged || scanTimer || guardianOwnMutation) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      scan();
    }, 1200);
  });

  installAdSpotListener();
  scan();
  if (!flagged && document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true,
      // Fake popups are often pre-built hidden and revealed with a style
      // or class flip, which is an attribute mutation, not an insertion.
      attributes: true,
      // "href" is here so an ad script rewriting an anchor's destination
      // triggers a fresh verdict instead of reusing the old one.
      attributeFilter: ["style", "class", "hidden", "href"]
    });
  }

  // -------------------------------------------------------------------------
  // The agent that runs INSIDE a third-party advert frame.
  //
  // It stays inert until the extension tells it the top page is a download
  // portal, and that message arrives over chrome.runtime, which the page
  // cannot forge.
  //
  // IT DOES NOT MODIFY ITS OWN DOCUMENT AT ALL. It only reports, and the top
  // frame draws an opaque cover over this whole frame, which is what actually
  // blocks the click. That division matters: anything this agent drew would be
  // clipped inside a 300x250 creative and never seen, and anything it disabled
  // would be stranded with no badge and no undo whenever the top frame
  // declined to draw (verification failure, a frame below the size floor, or
  // the per-page cap tripping). Reporting only means the visible warning and
  // the neutralization are always the same object, created and removed
  // together.
  // -------------------------------------------------------------------------
  function guardianAdFrameAgent(ctx) {
    let active = false;
    let reportedCount = 0;
    const AGENT_CAP = 2;

    chrome.runtime.onMessage.addListener((msg) => {
      if (!msg) return;
      if (msg.type === "guardianAdUndo") {
        active = false;
        return;
      }
      if (msg.type !== "guardianDownloadPortal") return;
      // Only act for the page we are actually embedded in.
      if (!msg.topOrigin || msg.topOrigin !== ctx.topOrigin) return;
      active = true;
      sweep();
    });

    // Frames can load or refresh after the top frame's one-shot broadcast, so
    // ask directly as well; the worker answers only from the recorded
    // top-frame origin, never from anything this frame claims.
    guardianSafeSend({ type: "portalStatus" }, (resp) => {
      if (!resp || !resp.topOrigin || resp.topOrigin !== ctx.topOrigin) return;
      active = true;
      sweep();
    });

    const seen = new WeakSet();

    function hostOfLocal(u) {
      try {
        return new URL(u).hostname.toLowerCase();
      } catch (e) {
        return "";
      }
    }

    // Exempt if ANY hop of the click chain is known-good. Exemptions must
    // cover at least as much ground as convictions: convicting on an unwrapped
    // hop while exempting only the literal href would judge a legitimate
    // vendor's installer by its ad tracker's hostname.
    function anyHopExempt(hops) {
      return hops.some((h) => {
        const hh = hostOfLocal(h);
        if (!hh) return false;
        return (
          guardianIsAllowlisted(hh) ||
          guardianHostOnList(hh, GUARDIAN_DOWNLOAD_SAFE_HOSTS) ||
          guardianSamePartyLabel(hh) === guardianSamePartyLabel(ctx.topHost)
        );
      });
    }

    function sweep() {
      if (!active || reportedCount >= AGENT_CAP) return;
      const anchors = Array.from(document.querySelectorAll("a[href]")).filter(
        (a) => /^https?:$/.test(a.protocol)
      );
      for (const a of anchors) {
        if (reportedCount >= AGENT_CAP) return;
        if (seen.has(a)) continue;
        const dest = a.href;
        const destHost = hostOfLocal(dest);
        if (!destHost) continue;
        const label = guardianOwnLabel(a);
        // The installer extension is a CANDIDACY signal only. It says "this
        // control hands over a program", which is what makes it worth judging.
        // It is never itself a reason to act.
        const isDl =
          guardianIsDownloadLabel(label) || GUARDIAN_INSTALLER_RE.test(dest);
        if (!isDl) continue;
        if (GUARDIAN_DOCUMENT_RE.test(dest)) continue;
        if (!guardianControlShapeOk(a)) continue;

        const hops = guardianUnwrapClick(dest);
        if (!hops.length || anyHopExempt(hops)) continue;

        // CONVICTION, and the only two forms of it, exactly as in PATH A:
        // a curated decoy network, or the threat feed. There is deliberately
        // no "it ends in .exe so it must be fake" rule: a legitimate vendor
        // advert (a real antivirus, a printer driver) links straight to an
        // installer, and convicting on that would disable honest advertising
        // on evidence no one can audit.
        const decoyHop = hops.find((h) =>
          guardianHostOnList(hostOfLocal(h), GUARDIAN_DECOY_NETWORKS)
        );
        if (decoyHop) {
          seen.add(a);
          report("decoy", hostOfLocal(decoyHop));
          continue;
        }
        guardianSafeSend({ type: "checkUrlsEach", urls: [dest] }, (resp) => {
          if (!resp) return; // no answer: retry on the next sweep
          seen.add(a);
          if (resp.bad && resp.bad.length) report("blocked", destHost);
        });
      }
    }

    // Ask the top frame to cover this whole frame. The message carries no
    // evidence the top frame acts on: it re-derives everything itself, and
    // treats the host purely as a string to display.
    function report(kind, destHost) {
      if (reportedCount >= AGENT_CAP) return;
      reportedCount++;
      try {
        window.top.postMessage(
          {
            __guardian: "adspot-v1",
            kind: kind === "blocked" ? "blocked" : "decoy",
            dest: String(destHost || "").slice(0, 100)
          },
          "*"
        );
      } catch (e) {
        // top frame unreachable: nothing has been changed here, so nothing
        // needs undoing
      }
    }

    // Creatives build themselves after load, so keep watching, debounced.
    let t = null;
    new MutationObserver(() => {
      if (!active || t || reportedCount >= AGENT_CAP) return;
      t = setTimeout(() => {
        t = null;
        sweep();
      }, 800);
    }).observe(document.documentElement, { childList: true, subtree: true });
  }
})();
