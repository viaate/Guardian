// Runs only on mail.google.com. Watches for opened emails and scores each
// one with the shared engine, plus email-specific link analysis. Gmail
// renders an opened message body in a div with class "a3s"; the subject is
// the h2.hP element; the sender address is on span.gD's email attribute.

(() => {
  const SCANNED_ATTR = "data-guardian-scanned";
  const FLAGGED_ATTR = "data-guardian-flagged";

  function currentSubject() {
    const el = document.querySelector("h2.hP");
    return el ? el.textContent : "";
  }

  // The sender's organisation. Uses the ccTLD-aware table from detector.js:
  // taking the last two labels treats every .co.uk address as the same
  // organisation, so a message from a look-alike .co.uk domain read as coming
  // from the real company's domain.
  function registrable(hostname) {
    const host = (hostname || "").toLowerCase();
    if (!host) return "";
    if (typeof guardianSamePartyLabel === "function") {
      const label = guardianSamePartyLabel(host);
      const parts = host.split(".").filter(Boolean);
      const i = parts.lastIndexOf(label);
      if (i !== -1) return parts.slice(i).join(".");
    }
    return host.split(".").slice(-2).join(".");
  }

  function findSender(bodyEl) {
    const message = bodyEl.closest("div.gs") || document;
    const el = message.querySelector("span.gD[email]");
    return {
      email: el ? el.getAttribute("email") || "" : "",
      name: el ? el.getAttribute("name") || el.textContent || "" : ""
    };
  }

  function senderDomainOf(senderEmail) {
    const at = senderEmail.lastIndexOf("@");
    return at === -1 ? "" : registrable(senderEmail.slice(at + 1));
  }

  function collectLinkHosts(bodyEl) {
    const hosts = new Set();
    for (const a of bodyEl.querySelectorAll('a[href^="http"]')) {
      try {
        hosts.add(new URL(a.href).hostname.toLowerCase());
      } catch {}
      if (hosts.size >= 50) break;
    }
    return [...hosts];
  }

  function collectLinkUrls(bodyEl) {
    const urls = new Set();
    for (const a of bodyEl.querySelectorAll('a[href^="http"]')) {
      urls.add(a.href);
      if (urls.size >= 50) break;
    }
    return [...urls];
  }

  // Reply-To only appears in Gmail's DOM when the message shows it (the
  // details caret expanded, or a forwarded message that quotes headers).
  // Best-effort: pull "reply-to: name <addr>" or "reply-to: addr" from the
  // visible message text. When absent we simply skip this signal.
  function findReplyTo(bodyEl) {
    const scope = bodyEl.closest("div.gs") || bodyEl;
    const txt = (scope.innerText || "").slice(0, 8000);
    const m = txt.match(/reply[\s-]?to:\s*[^<\n]*<?\s*([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})/i);
    return m ? m[1] : "";
  }

  // A credential-bait hostname that does not belong to the sender. The
  // sender-domain comparison is the false-positive guard: a real company
  // emailing about your password links to its own domain.
  const BAIT_RE = /(login|log-in|signin|sign-in|secure|verif|password|passwd|webmail)/;

  function findSuspiciousLinkHost(linkHosts, senderDomain) {
    for (const host of linkHosts) {
      if (guardianIsAllowlisted(host)) continue;
      if (senderDomain && registrable(host) === senderDomain) continue;
      if (BAIT_RE.test(host)) return host;
    }
    return null;
  }

  function flagEmail(bodyEl, subject, reason) {
    if (bodyEl.getAttribute(FLAGGED_ATTR)) return;
    bodyEl.setAttribute(FLAGGED_ATTR, "1");

    // Warning first: it must never depend on the background worker.
    if (!bodyEl.parentElement.querySelector(".guardian-banner")) {
      const banner = guardianBuildBanner(reason, "inline", { source: "email" });
      bodyEl.parentElement.insertBefore(banner, bodyEl);
    }

    guardianSafeSend({
      type: "scamDetected",
      source: "email",
      label: subject ? subject.slice(0, 80) : "(no subject)",
      reason
    });
  }

  function scanEmailBody(bodyEl) {
    if (bodyEl.getAttribute(SCANNED_ATTR)) return;

    const text = (bodyEl.innerText || "").slice(0, 20000);
    // Do NOT mark it scanned yet. Gmail renders an empty shell first and fills
    // it in a moment later; marking on the way past meant the placeholder was
    // "scanned" and the real message that arrived after it never was.
    if (text.trim().length < 40) return;

    // Fingerprint the text that was actually judged. If Gmail later replaces
    // the body - a quoted thread expanding, a different message in the same
    // container - the content changes and it is scanned again, instead of
    // being skipped forever because the element was seen once.
    const seen = bodyEl.getAttribute(SCANNED_ATTR);
    const fingerprint = text.length + ":" + text.slice(0, 120);
    if (seen === fingerprint) return;
    bodyEl.setAttribute(SCANNED_ATTR, fingerprint);

    const subject = currentSubject();
    const sender = findSender(bodyEl);
    const senderDomain = senderDomainOf(sender.email);
    const linkHosts = collectLinkHosts(bodyEl);
    const linkUrls = collectLinkUrls(bodyEl);

    // Link check 1: any link already reported as phishing/malware? Checked
    // as full URLs so a bad shortener link matches without blocking the
    // whole shortener. Runs in the background worker against the local feed.
    if (linkUrls.length) {
      guardianSafeSend({ type: "checkHosts", urls: linkUrls }, (resp) => {
        if (resp && resp.blockedHost) {
          flagEmail(
            bodyEl,
            subject,
            guardianT("reason_reported_email_link", { host: resp.blockedHost })
          );
        }
      });
    }

    // Link check 2, sender spoofing, reply-to mismatch, and phrase scoring
    // in the shared engine.
    const result = guardianAnalyze({
      title: subject,
      text,
      hostname: "",
      hasPasswordField: false,
      hasEmailInput: false,
      suspiciousLinkHost: findSuspiciousLinkHost(linkHosts, senderDomain),
      spoofedBrand: guardianFindSpoofedBrand(sender.name, sender.email),
      senderEmail: sender.email,
      replyToDomain: guardianReplyToMismatch(sender.email, findReplyTo(bodyEl)),
      isEmail: true
    });

    if (result.isScam) flagEmail(bodyEl, subject, result.reason);
  }

  function sweep() {
    document
      .querySelectorAll("div.a3s:not([" + SCANNED_ATTR + "])")
      .forEach(scanEmailBody);
  }

  // Gmail is a single-page app; watch for message bodies appearing.
  const observer = new MutationObserver(() => {
    // Cheap debounce: sweep on the next frame, coalescing mutation bursts.
    if (observer._pending) return;
    observer._pending = true;
    requestAnimationFrame(() => {
      observer._pending = false;
      sweep();
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });

  sweep();
})();
