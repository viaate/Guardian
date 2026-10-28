// Guardian detection engine. Pure scoring logic plus the banner builder.
// Loaded before page-scan.js / gmail-scan.js, which call into it.

const GUARDIAN_SCORE_THRESHOLD = 6;
// Where a page that is plainly teaching about scams is held: below the caution
// strip (4), because such a page is not a risk at all and a strip on a library
// article is still a false alarm, just a quieter one.
const GUARDIAN_TEACHING_CAP = 3;

// Toll-free US numbers (800/833/844/855/866/877/888), the signature of
// tech-support scams, in any common formatting.
const GUARDIAN_TOLLFREE_RE =
  /(\+?1[\s.\-]?)?\(?8(00|33|44|55|66|77|88)\)?[\s.\-]?\d{3}[\s.\-]?\d{4}/;

// sendMessage that survives a stale extension context (a page that stayed
// open across an extension reload/update throws on chrome.runtime calls).
// Protection must never depend on a live background worker, so callers
// show the warning banner BEFORE calling this.
// Is this content script still connected to the extension?
//
// When the extension is reloaded or updated, every script already running in
// an open tab is cut off. chrome.runtime.id goes undefined, and touching most
// chrome APIs throws "Extension context invalidated". A page open across a
// reload would otherwise keep scanning and keep throwing.
function guardianContextAlive() {
  try {
    return !!(chrome && chrome.runtime && chrome.runtime.id);
  } catch (e) {
    return false;
  }
}

function guardianSafeSend(message, callback) {
  if (!guardianContextAlive()) return;
  try {
    chrome.runtime.sendMessage(message, (response) => {
      // This callback runs LATER, outside the try below. If the extension is
      // reloaded between the send and the reply - which happens constantly
      // during development, and on every update in the field - then merely
      // reading lastError throws, uncaught, from an anonymous frame. That is
      // the "Extension context invalidated" error seen on a stale tab.
      try {
        void chrome.runtime.lastError; // swallow "no receiving end" errors
        if (callback) callback(response);
      } catch (inner) {
        // the extension went away mid-flight; nothing left to do here
      }
    });
  } catch (e) {
    // Stale context: stats/notification are lost for this page, but the
    // in-page warning already happened.
  }
}

// A brand word inside a larger financial-institution name is a DIFFERENT
// organization, not the brand: "Apple Federal Credit Union" is not Apple.
// Stripping these before brand matching prevents the worst class of false
// positive (real credit unions named after a brand word).
const GUARDIAN_ORG_SUFFIX_RE_SRC =
  "\\s+(federal\\s+credit\\s+union|credit\\s+union|employees\\s+credit\\s+union|" +
  "federal\\s+savings(\\s+bank)?|savings\\s+bank|fcu)\\b";

function guardianStripOrgNames(text, brandName) {
  const re = new RegExp(
    brandName.replace(/ /g, "\\s+") + GUARDIAN_ORG_SUFFIX_RE_SRC,
    "gi"
  );
  return (text || "").replace(re, " ");
}

// Sender spoofing: the display name or the sending domain claims a brand,
// but the actual sending domain is not the brand's. Word-boundary matching
// keeps Applebee's from matching Apple and "groups.io" from matching UPS.
function guardianFindSpoofedBrand(senderName, senderEmail) {
  const email = (senderEmail || "").toLowerCase();
  const at = email.lastIndexOf("@");
  const domain = at === -1 ? "" : email.slice(at + 1);
  const registrable = domain.split(".").slice(-2).join(".");
  const name = (senderName || "").toLowerCase();

  for (const brand of GUARDIAN_BRANDS) {
    const isRealSender = brand.domains.some(
      (d) => registrable === d || domain === d || domain.endsWith("." + d)
    );
    if (isRealSender) continue;
    const pattern = new RegExp(
      "(^|[^a-z0-9])" + brand.name.replace(/ /g, "[\\s._-]*") + "($|[^a-z0-9])"
    );
    // Strip org names first: "Apple Federal Credit Union" is a real,
    // different institution, not someone spoofing Apple.
    const strippedName = guardianStripOrgNames(name, brand.name);
    if (pattern.test(strippedName) || pattern.test(domain)) {
      return { display: brand.display, realDomain: brand.domains[0] };
    }
  }
  return null;
}

function guardianIsAllowlisted(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host) return false;
  if (
    typeof GUARDIAN_ALLOWLIST !== "undefined" &&
    GUARDIAN_ALLOWLIST.some((d) => host === d || host.endsWith("." + d))
  ) {
    return true;
  }
  // Entire trusted TLDs (.gov, .mil, .edu): registration is controlled,
  // so any host under them is the real organization.
  return (
    typeof GUARDIAN_ALLOWLIST_SUFFIXES !== "undefined" &&
    GUARDIAN_ALLOWLIST_SUFFIXES.some((s) => host.endsWith(s))
  );
}

// Plain Levenshtein with an early exit once the distance exceeds max.
function guardianEditDistance(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = [];
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

// Typosquat check: is this hostname's registered name one or two characters
// away from a known reputable name (paypa1.com, wallmart.com, robiox.com.py)?
// Uses the ccTLD-aware label so "www.robiox.com.py" reads "robiox", not "com".
// Also compares look-alike-normalized forms so g00gle -> google is caught.
// Short names are skipped; near-misses among short words are too common.
// The names worth protecting: everything on the allowlist, every known brand,
// and the popular-site list in data/typo-targets.js. Built once and cached:
// it is a few thousand entries and guardianTyposquatOf runs per hostname.
let guardianTypoTargetCache = null;
let guardianBroadOnlyCache = null;
function guardianTypoTargets() {
  if (guardianTypoTargetCache) return guardianTypoTargetCache;
  const targets = new Set();
  const core = new Set();
  if (typeof GUARDIAN_ALLOWLIST !== "undefined") {
    for (const d of GUARDIAN_ALLOWLIST) core.add(guardianRegistrableLabel(d));
  }
  if (typeof GUARDIAN_BRANDS !== "undefined") {
    for (const b of GUARDIAN_BRANDS) {
      for (const d of b.domains) core.add(guardianRegistrableLabel(d));
    }
  }
  for (const c of core) targets.add(c);

  // Names from the broad popular-site list are tracked separately, because a
  // near-miss against one of them carries less weight than a near-miss against
  // a bank on the allowlist. See guardianTypoTargetIsBroad.
  const broad = new Set();
  if (typeof GUARDIAN_TYPO_TARGETS !== "undefined") {
    for (const d of GUARDIAN_TYPO_TARGETS) {
      const l = guardianRegistrableLabel(d);
      targets.add(l);
      if (!core.has(l)) broad.add(l);
    }
  }
  guardianBroadOnlyCache = broad;
  guardianTypoTargetCache = targets;
  return targets;
}

// Did this typosquat target come ONLY from the broad popular-site list?
// Those matches are scored below the caution threshold on their own: measured
// across 6000 real popular sites, the broad list is where the residual
// edit-distance collisions live (coloradoan.com ~ colorado,
// nation.co.ke ~ notion), and a single near-miss on a name nobody is being
// phished with is not grounds to put a warning strip on a newspaper.
function guardianTypoTargetIsBroad(label) {
  if (!guardianBroadOnlyCache) guardianTypoTargets();
  return !!guardianBroadOnlyCache && guardianBroadOnlyCache.has(label);
}

function guardianTyposquatOf(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host || guardianIsAllowlisted(host)) return null;
  const sld = guardianRegistrableLabel(host);
  if (!sld || sld.length < 6) return null;
  const sldNorm = guardianDeglyph(sld);
  const targets = guardianTypoTargets();

  // An exact match means the real name on another TLD or subdomain layout;
  // that is the brand-impersonation check's job, not a typo.
  if (targets.has(sld)) return null;

  // The omitted dot after "www": wwwpaypal.com, wwwnetflix.com. Edit distance
  // can never catch this (three inserted characters), but requiring an EXACT
  // match on the remainder makes it close to free of false positives.
  if (sld.length > 7 && sld.startsWith("www")) {
    const rest = sld.slice(3);
    if (rest.length >= 5 && targets.has(rest)) return rest;
  }

  const max = sld.length >= 10 ? 2 : 1;
  for (const target of targets) {
    if (target.length < 6) continue;
    if (guardianEditDistance(sld, target, max) <= max) return target;
    // Look-alike match (g00gle -> google) when raw edit distance would miss it.
    if (sld !== target && sldNorm === guardianDeglyph(target)) return target;
  }
  return null;
}

// Is this host <brand>.<com|co|net|org>.<cc> - a country registration, rather
// than a brand planted in someone else's domain? amazon.com.be, ups.com.do,
// walmart.com.gt are all the real companies. There are roughly 200 such
// registries and no hand-kept suffix table will ever hold them all, so this is
// judged by SHAPE. The exception is a throwaway TLD that exists mostly for
// abuse, where a brand-shaped registration is the classic impostor and
// essentially never genuine: roblox.com.ml stays caught.
function guardianIsCountryRegistration(hostname, brandCompact) {
  const labs = (hostname || "").toLowerCase().split(".").filter(Boolean);
  if (labs[0] === "www") labs.shift();
  if (labs.length !== 3) return false;
  if (labs[0] !== brandCompact) return false;
  if (!GUARDIAN_TLD_WORDS.has(labs[1])) return false;
  if (!/^[a-z]{2}$/.test(labs[2])) return false;
  return !GUARDIAN_ABUSE_TLDS.includes("." + labs[2]);
}

function guardianBrandForHost(hostname) {
  const host = (hostname || "").toLowerCase();
  return GUARDIAN_BRANDS.find((b) =>
    b.domains.some((d) => host === d || host.endsWith("." + d))
  );
}

// Naive registrable domain: last two labels. Good enough to tell
// secured-login.net from mycreditunion.org; imperfect for country TLDs
// like .co.uk (see guardianRegistrableLabel for the ccTLD-aware version).
function guardianRegistrable(hostname) {
  return (hostname || "").toLowerCase().split(".").slice(-2).join(".");
}

// Common multi-part public suffixes, so ebay.co.uk reduces to "ebay", not
// "co". Not the full Public Suffix List, but covers the ccTLDs that show up
// for major brands. Used to tell a brand's OWN country/gTLD site apart from
// a brand name buried in an attacker's domain (paypal.com.evil.net).
const GUARDIAN_MULTI_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "co.jp", "or.jp", "ne.jp",
  "com.au", "net.au", "org.au", "co.nz", "com.br", "com.mx", "com.ar",
  "co.za", "com.tr", "co.in", "com.sg", "com.hk", "com.tw", "co.kr",
  "com.cn", "com.ua", "co.il", "com.my", "com.ph", "com.vn", "com.eg",
  "com.sa", "com.co", "com.pe", "com.pl", "co.th", "com.ng", "com.pk",
  "com.py", "com.ve", "com.ec", "com.bo", "com.cl", "com.uy", "co.id"
]);

// Further multi-part suffixes used ONLY by the "are these two hosts the same
// party?" comparison in the download-ad neutralizer.
//
// Deliberately NOT merged into GUARDIAN_MULTI_SUFFIXES above. That set feeds
// guardianRegistrableLabel, which the TYPOSQUAT check reads, so widening it
// silently changes which hostnames get compared against the look-alike target
// list. Adding co.ke there, for example, makes Kenya's nation.co.ke reduce to
// "nation" - one letter from the allowlisted "notion" - and puts a warning
// strip on a national newspaper. Same-party matching wants a wide list;
// typosquat matching wants a conservative one. They are different questions.
const GUARDIAN_SAMEPARTY_SUFFIXES = new Set([
  "nhs.uk", "gov.au", "edu.au", "net.au", "id.au", "net.nz", "org.nz",
  "govt.nz", "co.at", "or.at", "com.pt", "com.gr", "com.ro", "com.cy",
  "com.mt", "co.ke", "com.gh", "com.bd", "com.np", "com.lk", "or.kr",
  "ne.kr", "co.ma", "com.qa", "com.kw", "com.bh", "com.om", "com.lb",
  "com.jo", "com.do", "com.gt", "com.sv", "com.hn", "com.ni", "com.pa",
  "com.pr", "com.cu", "com.jm", "com.tt", "com.bs", "com.bz", "com.gy",
  "co.cr", "com.ht", "com.aw", "com.ge", "com.az", "com.kz", "com.uz"
]);

// The registrable label: the single name a domain is registered under
// (ebay.co.uk -> "ebay", paypal.com.evil.net -> "evil").
function guardianRegistrableLabel(hostname) {
  const parts = (hostname || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length < 2) return hostname || "";
  const last2 = parts.slice(-2).join(".");
  if (GUARDIAN_MULTI_SUFFIXES.has(last2) && parts.length >= 3) {
    return parts[parts.length - 3];
  }
  return parts[parts.length - 2];
}

// The registrable label for "are these the same party?" questions, which can
// afford a much wider suffix list than the typosquat comparison can. Being
// wrong here only means Guardian declines to act; being wrong in
// guardianRegistrableLabel means it acts on a legitimate site.
function guardianSamePartyLabel(hostname) {
  const parts = (hostname || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length < 2) return hostname || "";
  const last2 = parts.slice(-2).join(".");
  if (
    (GUARDIAN_MULTI_SUFFIXES.has(last2) || GUARDIAN_SAMEPARTY_SUFFIXES.has(last2)) &&
    parts.length >= 3
  ) {
    return parts[parts.length - 3];
  }
  return parts[parts.length - 2];
}

// TLDs that are cheap, loosely policed, and heavily over-represented in
// phishing. Presence is a weak reputation signal, not proof. Used only for
// the AI reputation SUMMARY (not scoring), so it can include borderline ones.
const GUARDIAN_RISKY_TLDS = [
  ".zip", ".mov", ".top", ".xyz", ".club", ".online", ".site", ".live",
  ".click", ".link", ".work", ".gq", ".tk", ".ml", ".cf", ".ga", ".rest",
  ".country", ".kim", ".loan", ".men", ".date", ".racing", ".win", ".bid",
  ".stream", ".download", ".icu", ".cyou", ".sbs", ".autos", ".lol"
];

// The NARROW subset that actually adds to the score: cheap TLDs that are
// overwhelmingly phishing and almost never legitimate. Deliberately excludes
// .dev/.app/.me/.io/.co/.cc/.xyz because real sites use those, and scoring
// them would spike the false-positive rate.
const GUARDIAN_ABUSE_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".cfd", ".sbs", ".cyou", ".icu",
  ".top", ".rest", ".quest", ".bond", ".autos", ".lol", ".click", ".work",
  ".bid", ".loan", ".men", ".date", ".racing", ".win", ".download", ".kim"
];

// Free / instant hosting platforms. Legit developers use these too, so being
// hosted here is NEVER a scam signal on its own. But a page that imitates a
// BRAND LOGIN and is hosted on throwaway infrastructure is high-confidence
// phishing: a real company's login lives on the company's own domain.
const GUARDIAN_FREE_HOSTS = [
  "github.io", "vercel.app", "netlify.app", "pages.dev", "web.app",
  "firebaseapp.com", "glitch.me", "repl.co", "replit.app", "onrender.com",
  "edgeone.dev", "edgeone.app", "awsapprunner.com", "oortstorages.com",
  "temporary.site", "wixsite.com", "weebly.com", "blogspot.com",
  "godaddysites.com", "workers.dev", "r2.dev", "surge.sh", "herokuapp.com",
  "framer.app", "webflow.io", "square.site", "notion.site", "gitbook.io",
  "000webhostapp.com", "infinityfreeapp.com", "dothome.co.kr",
  "webcindario.com", "servernotification.events"
];
function guardianOnFreeHost(hostname) {
  const host = (hostname || "").toLowerCase();
  return GUARDIAN_FREE_HOSTS.some((h) => host === h || host.endsWith("." + h));
}

// Normalize common look-alike substitutions so g00gle/paypa1/amaz0n compare
// to their real names. Deliberately small to avoid mangling ordinary words.
function guardianDeglyph(s) {
  return (s || "")
    .toLowerCase()
    .replace(/rn/g, "m").replace(/vv/g, "w")
    .replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e")
    .replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/\$/g, "s");
}

// TLD words a phishing host places right after a brand to mimic the real
// domain: "roblox.com.ml", "paypal.com.secure.tk".
const GUARDIAN_TLD_WORDS = new Set(["com", "net", "org", "co", "gov", "www"]);

// High-confidence brand mimic: a brand name appears as a full label that is
// immediately followed by a TLD-word ("brand.com.<something>") while the host
// is NOT the brand's real domain. This is the classic look-alike, and almost
// never a false positive: legit sites do not nest brand.com.realtld.
// (roblox.fandom.com is NOT caught, because "fandom" is not a TLD word.)
function guardianBrandMimic(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host || guardianIsAllowlisted(host)) return null;
  const labs = host.split(".").filter(Boolean);
  // The genuinely registered name. If the brand IS this name, the domain is a
  // real brand-on-a-ccTLD registration (ebay.co.uk), not a subdomain mimic.
  const regLabel = guardianRegistrableLabel(host);
  for (let i = 0; i < labs.length - 1; i++) {
    if (!GUARDIAN_TLD_WORDS.has(labs[i + 1])) continue;
    const label = labs[i];
    if (label === regLabel) continue; // brand is the registered name, not a subdomain

    // <brand>.<com|co|net|org>.<cc> with NOTHING after it is the shape of a
    // real country registration, not a subdomain mimic: citibank.com.do is
    // Citi in the Dominican Republic, walmart.com.gt is Walmart Guatemala,
    // amazon.com.be is Amazon Belgium. There are roughly 200 such registries
    // and GUARDIAN_MULTI_SUFFIXES can never list them all, so this is judged
    // by SHAPE rather than by table lookup.
    //
    // The exception is a throwaway TLD that exists mostly for abuse, where a
    // brand-shaped registration is the classic mimic and essentially never
    // legitimate: roblox.com.ml stays caught.
    const tail = labs.slice(i + 2);
    const bareCountry =
      tail.length === 1 &&
      /^[a-z]{2}$/.test(tail[0]) &&
      !GUARDIAN_ABUSE_TLDS.includes("." + tail[0]);
    if (bareCountry) continue;
    const brand = GUARDIAN_BRANDS.find((b) => {
      const core = b.name.replace(/ /g, "");
      return label === core || guardianDeglyph(label) === guardianDeglyph(core);
    });
    if (!brand) continue;
    const onReal = brand.domains.some((d) => host === d || host.endsWith("." + d));
    if (!onReal) return { display: brand.display, realDomain: brand.domains[0] };
  }
  return null;
}

// Scam-phrase categories mapped to one short, concrete line each.
const GUARDIAN_SIGNAL_KEYS = {
  techSupport: "signal_virus",
  threats: "signal_threats",
  credentials: "signal_credentials",
  delivery: "signal_delivery",
  prizes: "signal_prizes",
  payment: "signal_payment",
  giftCardAsk: "signal_giftcard",
  renewalScam: "signal_bill",
  cryptoSeed: "signal_crypto",
  urgency: "signal_urgency"
};

// What is actually wrong with this ADDRESS, in plain language. Everything here
// is computed on this machine from the address itself.
function guardianAddressSignals(hostname) {
  const host = (hostname || "").toLowerCase();
  const out = [];
  if (!host) return out;
  const look = guardianLookalikeHost(host) || guardianTyposquatOf(host);
  if (look) out.push(guardianT("signal_lookalike", { target: look }));
  const tld = GUARDIAN_RISKY_TLDS.find((t) => host.endsWith(t));
  if (tld) out.push(guardianT("signal_tld", { tld }));
  if (host.indexOf("xn--") !== -1) out.push(guardianT("signal_punycode"));
  const sld = guardianRegistrableLabel(host);
  if ((sld.match(/-/g) || []).length >= 3) out.push(guardianT("signal_hyphens"));
  if (/[a-z]/.test(sld) && (sld.match(/d/g) || []).length >= 3) {
    out.push(guardianT("signal_digits"));
  }
  return out;
}

// A HIGH-CONFIDENCE look-alike: either a brand mimic (paypal.com.evil.net) or
// a glyph-exact impostor (paypa1.com, faceb00k.com). Returns the real name it
// is imitating, or null.
//
// This deliberately EXCLUDES the plain edit-distance typosquat path, which is
// calibrated for judging one page's own hostname. Measured against 6000 real
// popular sites, edit distance alone matches 0.40% of them while the two
// signals used here match none. That difference does not matter for a single
// hostname, but it decides everything when the test is applied to every link
// on a page: at 0.40% a page with eighty links would raise a false alarm about
// one in four times, whereas these two signals stay quiet.
function guardianLookalikeHost(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host || guardianIsAllowlisted(host)) return null;

  const mimic = guardianBrandMimic(host);
  if (mimic) return mimic.display;

  const target = guardianTyposquatOf(host);
  if (!target) return null;
  const sld = guardianRegistrableLabel(host);

  // Digit-for-letter and look-alike-character impostors: paypa1, faceb00k.
  if (sld !== target && guardianDeglyph(sld) === guardianDeglyph(target)) {
    return target;
  }
  // The omitted dot after www: wwwpaypal.com. This one is high confidence for
  // the same reason the glyph test is - it requires an EXACT match on the
  // remainder, not a near-miss - so it belongs with the strong signals rather
  // than with the edit-distance ones.
  if (sld === "www" + target) return target;

  return null;
}

// A short, plain-language summary of LOCAL reputation red flags for a
// hostname. Everything here is computed on-device from the address itself;
// no external reputation service is queried, which would mean sending the
// address off the machine. Used only to give the on-device AI more to go on.
function guardianReputationSummary(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host) return "no web address (local file)";
  if (guardianIsAllowlisted(host)) return "a well-known, trusted website";

  const notes = [];
  // The flat claim is reserved for the high-confidence path (glyph-exact or
  // brand mimic), which matched none of 6000 real popular sites. A plain
  // edit-distance near-miss is hedged instead: the model is told to weigh the
  // address heavily, so handing it "spelled almost like X" as a fact about a
  // legitimate newspaper is how a weak signal becomes a full-page takeover.
  const strong = guardianLookalikeHost(host);
  if (strong) {
    notes.push("spelled almost like the real " + strong);
  } else {
    const typo = guardianTyposquatOf(host);
    if (typo) {
      notes.push(
        "slightly similar to the name " + typo + ", which may well be a coincidence"
      );
    }
  }

  const brand = GUARDIAN_BRANDS.find((b) => {
    if (b.domains.some((d) => host === d || host.endsWith("." + d))) return false;
    const re = new RegExp(
      "(^|[^a-z0-9])" + b.name.replace(/ /g, "[\\s._-]*") + "($|[^a-z0-9])"
    );
    return re.test(host);
  });
  if (brand) notes.push("contains the brand name " + brand.display + " but is not its real site");

  const tld = GUARDIAN_RISKY_TLDS.find((t) => host.endsWith(t));
  if (tld) notes.push("uses an unusual address ending (" + tld + ") often seen in scams");

  const sld = host.split(".").slice(-2)[0] || "";
  if ((sld.match(/-/g) || []).length >= 3) notes.push("address has many hyphens");
  if (/\d/.test(sld) && /[a-z]/.test(sld) && (sld.match(/\d/g) || []).length >= 3) {
    notes.push("address mixes many digits into a word");
  }
  if (host.includes("xn--")) notes.push("uses foreign look-alike characters (punycode)");

  return notes.length ? notes.join("; ") : "no obvious red flags in the address itself";
}

// Reply-To vs From: a legit sender's reply address is on its own domain.
// Scammers set Reply-To to an address they control so a reply reaches them
// even when the visible From is spoofed. Returns the reply-to registrable
// domain when it differs from the From domain, else null.
function guardianReplyToMismatch(fromEmail, replyToEmail) {
  const fromAt = (fromEmail || "").toLowerCase().lastIndexOf("@");
  const replyAt = (replyToEmail || "").toLowerCase().lastIndexOf("@");
  if (fromAt === -1 || replyAt === -1) return null;
  // Same-party comparison, so two different organisations under .co.uk are
  // not read as one. guardianRegistrable takes the last two labels, which
  // makes every .co.uk address look like the same domain.
  const fromDom = guardianSamePartyLabel(fromEmail.slice(fromAt + 1));
  const replyDom = guardianSamePartyLabel(replyToEmail.slice(replyAt + 1));
  if (!fromDom || !replyDom || fromDom === replyDom) return null;
  if (guardianIsAllowlisted(replyDom)) return null; // reply goes to a trusted domain
  return replyDom;
}

// Score a chunk of content. Returns { isScam, score, reason, categories }.
// opts: { title, text, hostname, hasPasswordField, isEmail }
function guardianAnalyze(opts) {
  const title = (opts.title || "").toLowerCase();
  const text = (opts.text || "").toLowerCase();
  const combined = title + "\n" + text;

  let score = 0;
  const matched = []; // [{ category, weight, reasonKey }]

  for (const [category, def] of Object.entries(GUARDIAN_PHRASES)) {
    if (def.phrases.some((p) => combined.includes(p))) {
      score += def.weight;
      matched.push({ category, weight: def.weight, reasonKey: def.reasonKey });
    }
  }

  const has = (cat) => matched.some((m) => m.category === cat);

  // A toll-free number is damning next to tech-support text, strong next
  // to fake-bill text (the call-to-cancel invoice scam), mildly suspicious
  // next to threats or urgency, meaningless on its own.
  if (GUARDIAN_TOLLFREE_RE.test(combined)) {
    if (has("techSupport")) score += 3;
    else if (has("renewalScam")) score += 2;
    else if (has("threats") || has("urgency")) score += 1;
  }

  // Fake sign-in page clones: distinctive real-login-screen wording plus a
  // credential input on a domain that is not the real one. This is the page
  // where a password would actually be stolen, so it flags instantly.
  // Covers browser-in-the-browser fakes too: those copy Google's two-step
  // flow, so the first screen has only an email/phone box and no password
  // field yet. A password field plus one distinctive phrase is conclusive;
  // an email input alone requires two phrases, so an article quoting the
  // sign-in screen next to a newsletter box cannot match.
  let cloneReason = null;
  if (!opts.isEmail && (opts.hasPasswordField || opts.hasEmailInput)) {
    const host = (opts.hostname || "").toLowerCase();
    for (const clone of GUARDIAN_LOGIN_CLONES) {
      const onRealDomain = clone.domains.some(
        (d) => host === d || host.endsWith("." + d)
      );
      if (onRealDomain) continue;
      const hits = clone.phrases.filter((p) => combined.includes(p)).length;
      if ((opts.hasPasswordField && hits >= 1) || (opts.hasEmailInput && hits >= 2)) {
        score += 6;
        cloneReason = guardianT("reason_clone", {
          brand: clone.display,
          domain: clone.homeDomain
        });
        break;
      }
    }
  }

  // Address-based signals (websites only).
  let typoReason = null;
  let mimicReason = null;
  if (!opts.isEmail) {
    // Brand mimic: "roblox.com.ml", "paypal.com.evil.tk". Very high
    // confidence and rarely a false positive, so it flags on the address
    // alone even when the login form is rendered later by JavaScript.
    const mimic = guardianBrandMimic(opts.hostname);
    if (mimic) {
      score += 6;
      mimicReason = guardianT("reason_brand", { brand: mimic.display });
    }

    // Lookalike domains. Two confidence levels, because a plain letter-swap
    // collides with real words (fetlife~metlife, hicloud~icloud, inleed~indeed)
    // far more than a digit/look-alike substitution does:
    //  - glyph-exact (paypa1->paypal, amaz0n->amazon): high confidence.
    //  - edit-distance letter swap: lower; needs a corroborating signal to flag.
    const typoTarget = guardianTyposquatOf(opts.hostname);
    if (typoTarget) {
      const sld = guardianRegistrableLabel((opts.hostname || "").toLowerCase());
      // Glyph swap (paypa1 -> paypal) or the omitted dot after www
       // (wwwpaypal -> paypal). Both demand an exact match once normalised,
       // which is why they carry the weight a plain near-miss does not.
      const glyphExact =
        (sld !== typoTarget && guardianDeglyph(sld) === guardianDeglyph(typoTarget)) ||
        sld === "www" + typoTarget;
      const cred = opts.hasPasswordField || opts.hasEmailInput;
      if (glyphExact) {
        // Flags on the address alone, with no login box required. paypa1.com
        // and wwwpaypal.com are not legitimate sites that happen to look odd;
        // the whole point of registering them is impersonation, and the page
        // behind one is usually a redirector with no form on it at all. This
        // is the same evidence bar used for the link check: zero false
        // positives across 12,000 real popular sites.
        score += 6;
      } else if (guardianTypoTargetIsBroad(typoTarget)) {
        // Capped BELOW the caution threshold (4) on purpose: a plain
        // letter-swap against a merely-popular name must never put a warning
        // strip on a legitimate site by itself. It can still corroborate.
        score += cred ? 3 : 1;
      } else {
        score += cred ? 4 : 2;
      }
      typoReason = guardianT("reason_typo", { target: typoTarget });
    }

    // Punycode hostnames ("xn--") imitate real names using foreign characters.
    if ((opts.hostname || "").includes("xn--")) {
      score += opts.hasPasswordField || opts.hasEmailInput ? 4 : 2;
    }

    // Soft reputation signals: contribute points but never flag on their own,
    // so a legit site on a mixed-use TLD is never flagged by these alone.
    const host = (opts.hostname || "").toLowerCase();
    if (host && !guardianIsAllowlisted(host)) {
      if (GUARDIAN_ABUSE_TLDS.some((t) => host.endsWith(t))) score += 2;
      const sld = guardianRegistrableLabel(host);
      if (/[a-z]/.test(sld) && (sld.match(/\d/g) || []).length >= 3) score += 1;
    }
  }

  // Insecure login: a page asking for a password over plain HTTP (no
  // padlock) is either a scam or dangerously misconfigured. Real sign-in
  // pages are always HTTPS. Strong signal on its own.
  let insecureReason = null;
  if (!opts.isEmail && opts.insecureLogin) {
    score += 4;
    insecureReason = guardianT("reason_insecure");
  }

  // Brand impersonation: page leans on a brand name (in its text or in its
  // own hostname), is not on the real domain, and is fishing for
  // credentials. A brand inside the HOSTNAME (secure-chase-login.com) with
  // a credential input is conclusive on its own. Skipped for email (the
  // host there is always mail.google.com) and for hosts that ARE the brand.
  // An empty hostname (file:// pages) is by definition not the brand.
  let brandReason = null;
  if (!opts.isEmail && !guardianBrandForHost(opts.hostname || "")) {
    const head = combined.slice(0, 3000);
    const hostLower = (opts.hostname || "").toLowerCase();
    // guardianSamePartyLabel, NOT guardianRegistrableLabel: this decides
    // whether the brand IS this domain's registered name or is merely planted
    // in it, and the conservative suffix table does not know com.do, com.gt
    // and the rest. With the narrow table citibank.com.do reduces to "com",
    // which does not equal "citibank", so the real Citi in the Dominican
    // Republic read as a brand planted in someone else's domain and earned a
    // full-page "STOP. This is a scam." over an actual bank.
    const regLabel = guardianSamePartyLabel(hostLower);

    // A page that NAMES several different brands is a rewards / marketplace /
    // aggregator site (PrizeRebel lists PayPal, Apple, Amazon, Roblox...), not
    // an impersonation of any one of them. Real phishing targets exactly one
    // brand. When 3+ brands are named, the text-mention path is switched off
    // (the hostname path still applies: paypal.com.evil.tk is still caught).
    let mentions = 0;
    for (const b of GUARDIAN_BRANDS) {
      const re = new RegExp("\\b" + b.name.replace(/ /g, "\\s+") + "\\b", "i");
      if (re.test(guardianStripOrgNames(combined, b.name))) mentions++;
      if (mentions >= 3) break;
    }
    const aggregator = mentions >= 3;

    let brandInHost = false;
    const brand = GUARDIAN_BRANDS.find((b) => {
      const compact = b.name.replace(/ /g, "");
      const hostRe = new RegExp(
        "(^|[^a-z0-9])" + b.name.replace(/ /g, "[\\s._-]*") + "($|[^a-z0-9])"
      );
      // A brand name in the hostname is impersonation UNLESS the brand is
      // the domain's own registrable label (ebay.co.uk, amazon.dev are the
      // real brands; secure-chase-login.com and paypal.com.evil.net are not).
      if (
        hostRe.test(hostLower) &&
        regLabel !== compact &&
        !guardianIsCountryRegistration(hostLower, compact)
      ) {
        brandInHost = true;
        return true;
      }
      // Text-based impersonation requires more than a bare mention: a page
      // legitimately naming a brand ("redeem for PayPal") is not impersonating
      // it. It counts only when the brand is in the TITLE, or sits right next
      // to login wording in the body ("sign in to your PayPal account"). Org
      // names are stripped first (Apple Federal Credit Union is not Apple).
      if (aggregator) return false;
      const nameRe = b.name.replace(/ /g, "\\s+");
      const inTitle = new RegExp("\\b" + nameRe + "\\b", "i").test(
        guardianStripOrgNames(title, b.name)
      );
      if (inTitle) return true;
      const loginNear = new RegExp(
        "(sign\\s?in|log\\s?in|login|verify|unlock|access)[^.]{0,20}" + nameRe +
        "|" + nameRe + "[^.]{0,15}(account|login|sign\\s?in|password|wallet)",
        "i"
      );
      return loginNear.test(guardianStripOrgNames(head, b.name));
    });
    const credentialContext = brandInHost
      ? opts.hasPasswordField || opts.hasEmailInput || has("credentials")
      : opts.hasPasswordField || has("credentials");
    if (brand && credentialContext) {
      let add = brandInHost ? 6 : 5;
      // A brand login page on throwaway hosting (github.io, vercel.app,
      // edgeone.dev...) is almost certainly phishing: real logins live on the
      // brand's own domain. Pushes the many "brand + form" near-misses over.
      if (guardianOnFreeHost(opts.hostname)) add += 2;
      score += add;
      brandReason = guardianT("reason_brand", { brand: brand.display });
    }
  }

  // Sender spoofing (email only): the caller found a claimed brand that
  // does not match the sending address. Requires at least one non-urgency
  // scam category in the body so a real person named Chase writing
  // "do this right away" is never flagged as a fake bank.
  let spoofReason = null;
  if (
    opts.isEmail &&
    opts.spoofedBrand &&
    matched.some((m) => m.category !== "urgency")
  ) {
    score += 5;
    spoofReason = guardianT("reason_spoof", {
      brand: opts.spoofedBrand.display,
      sender: opts.senderEmail || guardianT("different_address"),
      domain: opts.spoofedBrand.realDomain
    });
  }

  // Scam emails give themselves away through their links: text about
  // passwords or accounts whose action link goes to an unrelated,
  // credential-bait domain (like secured-login.net). Legit password
  // emails link to the sender's own domain, which the caller has
  // already filtered out before setting suspiciousLinkHost.
  let linkReason = null;
  if (opts.isEmail && opts.suspiciousLinkHost && has("credentials")) {
    score += 5;
    linkReason = guardianT("reason_link", { host: opts.suspiciousLinkHost });
  }

  // Reply-To vs From mismatch (email only). Noisier than the other signals
  // (legit newsletters legitimately reply to a different domain), so it only
  // adds weight when the body already shows a non-urgency scam category.
  let replyToReason = null;
  if (
    opts.isEmail &&
    opts.replyToDomain &&
    matched.some((m) => m.category !== "urgency")
  ) {
    score += 2;
    replyToReason = guardianT("reason_replyto", { domain: opts.replyToDomain });
  }

  // A page that is TEACHING about a scam quotes the scam's own words, so it
  // scores like one. Cap it below the warning threshold - but only when the
  // case against the page rests on its wording ALONE. Every signal below is a
  // fact about the address, the sender or the form, and a fraud-alert page
  // does not sit on a look-alike domain, spoof a sender or ask for a password:
  // if any of them fired, the wording is not what convicted the page and the
  // cap must not apply. It only ever lowers a score, and only one that had
  // already crossed the warning line, so it can soften a verdict but never
  // create one.
  if (
    !cloneReason && !mimicReason && !typoReason && !spoofReason &&
    !linkReason && !replyToReason && !brandReason && !insecureReason &&
    score >= GUARDIAN_SCORE_THRESHOLD
  ) {
    const teaching = GUARDIAN_TEACHING_MARKERS.filter((m) => combined.includes(m));
    if (teaching.length >= 2) score = Math.min(score, GUARDIAN_TEACHING_CAP);
  }

  const isScam = score >= GUARDIAN_SCORE_THRESHOLD;
  let reason = "";
  if (isScam) {
    // Most specific explanation wins: a cloned sign-in page beats a
    // typosquatted domain beats a spoofed sender beats a suspicious email
    // link beats generic brand impersonation beats the highest-weight
    // matched category.
    if (cloneReason) {
      reason = cloneReason;
    } else if (mimicReason) {
      reason = mimicReason;
    } else if (typoReason) {
      reason = typoReason;
    } else if (spoofReason) {
      reason = spoofReason;
    } else if (linkReason) {
      reason = linkReason;
    } else if (replyToReason) {
      reason = replyToReason;
    } else if (brandReason) {
      reason = brandReason;
    } else if (insecureReason) {
      reason = insecureReason;
    } else if (matched.length) {
      matched.sort((a, b) => b.weight - a.weight);
      reason = guardianT(matched[0].reasonKey);
    } else {
      reason = guardianT("reason_generic");
    }
  }

  return { isScam, score, reason, categories: matched.map((m) => m.category) };
}

// ---------------------------------------------------------------------------
// Helpers for the download-ad neutralizer. Kept here so they are shared and
// individually testable (test-pages/neutralizer-selftest.html asserts them).
// NOTE: nothing here may reference data/ad-networks.js, because the Gmail
// content script loads this file without it.
// ---------------------------------------------------------------------------

// The text a person actually reads ON a control.
//
// Deliberately NOT innerText/textContent-without-a-cap: a listing card wrapped
// in one big <a> would report every word of its blurb, so any card whose
// description mentions "download" would look like a download button. Direct
// child text is tried first (the precise case), then the whole subtree, but
// anything longer than 60 characters is a card, not a button, and yields "".
function guardianOwnLabel(el) {
  if (!el) return "";
  const clean = (s) => (s || "").replace(/\s+/g, " ").trim();
  const capped = (s) => (s.length > 60 ? "" : s);

  let own = "";
  for (const node of el.childNodes) {
    if (node.nodeType === 3) own += node.nodeValue; // text node
  }
  own = clean(own);
  if (own) return capped(own);

  // <a><span>Download</span></a> is an extremely common button shape, so fall
  // back to the subtree, still under the 60-character card cap.
  const deep = clean(el.textContent);
  if (deep) return capped(deep);

  const aria = clean(el.getAttribute("aria-label"));
  if (aria) return capped(aria);
  const title = clean(el.getAttribute("title"));
  if (title) return capped(title);

  // An image-only creative: its alt text is the only label there is.
  const imgs = el.querySelectorAll("img");
  if (imgs.length === 1) {
    const alt = clean(
      (imgs[0].getAttribute("alt") || "") + " " + (imgs[0].getAttribute("title") || "")
    );
    if (alt) return capped(alt);
  }
  return "";
}

// Is this element shaped like a BUTTON (as opposed to a card, a row, or a
// tracking pixel)? Without this, a 900px card-wrapping anchor gets deadened
// along with the title link inside it.
function guardianControlShapeOk(el) {
  if (!el || !el.isConnected) return false;
  const r = el.getBoundingClientRect();
  if (!(r.width > 0 && r.height > 0)) return false;
  if (r.width > 420 || r.height > 140) return false;
  let cs = null;
  try {
    cs = getComputedStyle(el);
  } catch (e) {
    return false;
  }
  if (!cs) return false;
  if (cs.visibility === "hidden" || cs.display === "none") return false;
  if (parseFloat(cs.opacity || "1") <= 0.05) return false;
  // A control that contains other controls is a container, not a button.
  if (el.querySelector('a, button, input, select, textarea, [role="button"]')) {
    return false;
  }
  return true;
}

// Where is this frame, and who is the page the person thinks they are on?
//
// Uses location.ancestorOrigins, NOT document.referrer (which is the immediate
// parent, i.e. the ad server two or three hops below the portal) and NOT
// window.top.location (which throws SecurityError cross-origin).
// Fails CLOSED (returns null) whenever the answer is not certain, and returns
// null when this frame is the same party as the top page.
function guardianFrameContext() {
  let chain = null;
  try {
    chain = location.ancestorOrigins;
  } catch (e) {
    return null;
  }
  if (!chain || !chain.length) return null;

  const topOrigin = chain[chain.length - 1];
  if (!topOrigin || topOrigin === "null") return null; // opaque ancestor
  let topHost = "";
  try {
    topHost = new URL(topOrigin).hostname.toLowerCase();
  } catch (e) {
    return null;
  }
  if (!topHost) return null;

  // Our own origin. A sandboxed, data: or blob: creative reports "null", so
  // fall back to the nearest non-opaque ancestor, which is the ad server.
  let adHost = "";
  try {
    if (location.origin && location.origin !== "null") {
      adHost = new URL(location.origin).hostname.toLowerCase();
    }
  } catch (e) {
    adHost = "";
  }
  if (!adHost) {
    for (let i = 0; i < chain.length - 1; i++) {
      if (!chain[i] || chain[i] === "null") continue;
      try {
        adHost = new URL(chain[i]).hostname.toLowerCase();
      } catch (e) {
        adHost = "";
      }
      if (adHost) break;
    }
  }
  if (!adHost) return null;

  // Same party as the page: not a third-party advert, so not our business.
  if (guardianSamePartyLabel(adHost) === guardianSamePartyLabel(topHost)) {
    return null;
  }
  return { topOrigin, topHost, adHost };
}

// Map a message's source window back to the <iframe> in THIS document that
// contains it. Real creatives sit two or three frames deep (a GPT friendly
// frame inside a SafeFrame), so the source is usually not a direct child.
// Cross-origin WindowProxy identity comparison is allowed; contentDocument
// would be null.
function guardianIframeFor(win) {
  let w = win;
  let hops = 0;
  try {
    while (w && w.parent !== window && w.parent !== w && hops++ < 8) w = w.parent;
    if (!w || w.parent !== window) return null;
  } catch (e) {
    return null;
  }
  const frames = document.querySelectorAll("iframe");
  for (const f of frames) {
    try {
      if (f.contentWindow === w) return f;
    } catch (e) {
      // cross-origin access on this one is fine to skip
    }
  }
  return null;
}

// The cover drawn over a neutralized advert. The caller positions it.
// It always names the destination, so the person can check our claim, and it
// always offers a one-click undo.
function guardianBuildAdCover(destHost, kind, onUndo) {
  const cover = document.createElement("div");
  cover.className = "guardian-adcover";

  const badge = document.createElement("div");
  badge.className = "guardian-adcover-badge";
  // The strong "fake download" wording is reserved for a threat-feed hit,
  // where the claim is earned. Everything else gets the calm, true wording.
  badge.textContent =
    "⚠ " + guardianT(kind === "blocked" ? "adblock_badge" : "adblock_badge_ad");
  cover.appendChild(badge);

  if (destHost) {
    const dest = document.createElement("div");
    dest.className = "guardian-adcover-dest";
    dest.textContent = guardianT("adblock_dest", { host: destHost });
    cover.appendChild(dest);
  }

  const undo = document.createElement("button");
  undo.className = "guardian-adcover-undo";
  undo.textContent = guardianT("adblock_undo");
  undo.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (onUndo) onUndo();
  });
  cover.appendChild(undo);
  return cover;
}

// ---------------------------------------------------------------------------
// Warning UI. mode "page": full-screen takeover that covers the scam content
// entirely, with one giant safe action (Close this page) and a deliberately
// small escape hatch. mode "inline": large banner above an email body.
// ---------------------------------------------------------------------------

// "Close this page" has to work even when the page does not want it to.
//
// Two ways it silently did nothing. The extension context goes stale whenever
// the extension is reloaded while a tab is open, and the raw sendMessage call
// then throws, so the button did nothing at all. And a page can register a
// capture-phase click listener and stop the event before it ever reaches our
// button, which is exactly what a page trying to trap someone would do.
//
// So: never throw, and if the tab is somehow still here a moment later, get
// the person off the page anyway. A button labelled "Close this page" that
// does nothing is worse than useless to someone who is frightened.
function guardianCloseThisPage(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  try {
    chrome.runtime.sendMessage({ type: "closeTab" }, () => {
      try {
        void chrome.runtime.lastError;
      } catch (inner) {
        // extension gone mid-flight; the fallback below still gets them out
      }
    });
  } catch (err) {
    // stale extension context: the fallback below still gets them out
  }
  setTimeout(() => {
    try {
      window.close();
    } catch (err) {
      // not a script-opened window
    }
    try {
      location.replace("about:blank");
    } catch (err) {
      // nothing further we can do
    }
  }, 700);
}

function guardianBuildBanner(reason, mode, context) {
  context = context || {};
  const banner = document.createElement("div");
  banner.className = "guardian-banner";
  if (mode === "inline") banner.className += " guardian-inline";
  if (mode === "remote") banner.className += " guardian-remote";

  // Announced as a dialog, so a screen reader says a warning has appeared
  // instead of silently reading on. Without this the page underneath is still
  // the focus, and someone using a keyboard or a reader could carry on typing
  // into a scam form they were never told about.
  const headingId = "guardian-heading-" + Math.random().toString(36).slice(2, 9);
  if (mode !== "inline") {
    banner.setAttribute("role", "dialog");
    banner.setAttribute("aria-modal", "true");
    banner.setAttribute("tabindex", "-1");
  } else {
    banner.setAttribute("role", "alert");
  }
  banner.setAttribute("aria-labelledby", headingId);

  const icon = document.createElement("div");
  icon.className = "guardian-banner-icon";
  icon.textContent = "⚠"; // warning sign
  banner.appendChild(icon);

  const body = document.createElement("div");
  body.className = "guardian-banner-body";

  const heading = document.createElement("div");
  heading.className = "guardian-banner-heading";
  heading.id = headingId;
  heading.textContent =
    mode === "inline"
      ? guardianT("banner_heading_email")
      : mode === "remote"
        ? guardianT("remote_heading")
        : guardianT("banner_heading_page");
  body.appendChild(heading);

  const text = document.createElement("div");
  text.className = "guardian-banner-text";
  text.textContent = reason;
  body.appendChild(text);

  // WHY Guardian thinks so, as concrete findings. Without this the person is
  // asked to agree or disagree with a conclusion on no evidence: "several
  // signs of a scam" names none of them, and repeating the address back is no
  // help either, since it is already in the address bar above. These are the
  // findings themselves, so a person can judge for themselves whether we got
  // it right.
  if (mode === "page" && context.signals && context.signals.length) {
    const list = document.createElement("ul");
    list.className = "guardian-banner-signals";
    context.signals.slice(0, 4).forEach((s) => {
      const li = document.createElement("li");
      li.textContent = s;
      list.appendChild(li);
    });
    body.appendChild(list);
  }

  const actions = document.createElement("div");
  actions.className = "guardian-banner-actions";

  if (mode !== "inline") {
    const closeBtn = document.createElement("button");
    closeBtn.className = "guardian-btn-primary";
    closeBtn.textContent = guardianT("banner_close");
    closeBtn.addEventListener("click", guardianCloseThisPage);
    actions.appendChild(closeBtn);
  }

  const dismissBtn = document.createElement("button");
  dismissBtn.className = "guardian-btn-secondary";
  dismissBtn.textContent =
    mode === "inline"
      ? guardianT("banner_dismiss_email")
      : mode === "remote"
        ? guardianT("remote_dismiss")
        : guardianT("banner_dismiss_page");
  dismissBtn.__guardianRun = () => {
    banner.remove();
    if (banner.__guardianRelease) banner.__guardianRelease();
    // Dismissing IS the person telling us we got it wrong. Log it as a
    // false positive and, for full-page website warnings, remember this
    // site so Guardian stops warning on it. (Remote-tool cautions and the
    // demo never remember, and email dismissals only log.)
    try {
      chrome.runtime.sendMessage({
        type: "reportMistake",
        hostname: context.hostname || "",
        source: context.source || "website",
        remember: mode === "page" && !!context.hostname,
        reason
      });
    } catch (e) {
      // stale context or demo page: nothing to log, the banner is gone
    }
  };
  dismissBtn.addEventListener("click", () => dismissBtn.__guardianRun());
  actions.appendChild(dismissBtn);

  body.appendChild(actions);

  if (mode !== "inline") {
    const footer = document.createElement("div");
    footer.className = "guardian-banner-footer";
    footer.textContent = guardianT("banner_footer");
    body.appendChild(footer);
  }

  banner.appendChild(body);

  if (mode !== "inline") {
    // Keep the keyboard inside the warning. A full-screen warning that the
    // page can still be tabbed behind is only a warning for people using a
    // mouse: everyone else can keep typing into the form underneath.
    banner.addEventListener("keydown", (e) => {
      if (e.key !== "Tab") return;
      const focusable = banner.querySelectorAll("button, [href], [tabindex]:not([tabindex='-1'])");
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });
    // Move focus to the safe action, not into the page behind it.
    setTimeout(() => {
      const target = banner.querySelector(".guardian-btn-primary") || banner;
      try {
        target.focus();
      } catch (e) {
        // element gone already
      }
    }, 0);
  }

  // The page gets no chance to swallow clicks on our own buttons: this runs in
  // the capture phase on window, which is the earliest point in the path.
  // Removed with the banner, so a dismissed warning does not leave a listener
  // running on every click for the rest of the page's life.
  banner.__guardianRelease = () => {
    try {
      window.removeEventListener("click", onGuardianClick, true);
    } catch (e) {
      // nothing to release
    }
  };
  function onGuardianClick(e) {
    const t =
      e.target && e.target.closest
        ? e.target.closest(".guardian-btn-primary, .guardian-btn-secondary")
        : null;
    if (!t || !banner.contains(t)) return;
    e.stopImmediatePropagation();
    e.preventDefault();
    if (t.classList.contains("guardian-btn-primary")) guardianCloseThisPage();
    else dismissBtn.__guardianRun();
  }
  window.addEventListener("click", onGuardianClick, true);

  return banner;
}

// A soft caution strip for pages that MIGHT be a scam but are not certain.
// Non-invasive: a slim bar at the top of the page, easily dismissed, that
// does NOT cover the page. The full-screen takeover is reserved for confident
// scams.
// textKey/variantClass let the same strip carry calm advice (the blue
// download tip) as well as the amber "might be a scam" caution. Existing
// callers pass nothing and are unaffected.
function guardianBuildCaution(textKey, variantClass, onDismiss, dismissKey) {
  const bar = document.createElement("div");
  bar.className = "guardian-caution" + (variantClass ? " " + variantClass : "");

  const icon = document.createElement("span");
  icon.className = "guardian-caution-icon";
  icon.textContent = "⚠";

  const msg = document.createElement("span");
  msg.className = "guardian-caution-text";
  msg.textContent = guardianT(textKey || "caution_text");

  const btn = document.createElement("button");
  btn.className = "guardian-caution-dismiss";
  btn.textContent = guardianT(dismissKey || "caution_dismiss");
  btn.addEventListener("click", () => {
    bar.remove();
    if (onDismiss) onDismiss();
  });

  bar.appendChild(icon);
  bar.appendChild(msg);
  bar.appendChild(btn);
  return bar;
}
