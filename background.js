// Guardian service worker: stats, notifications, the close-tab rescue,
// and the reported-scam blocklist (local copy of the OpenPhish feed).

importScripts("data/strings.js", "data/allowlist.js", "data/ad-networks.js");

// A trusted site is NEVER blocked, even if it appears in a threat feed.
// Phishing is often hosted ON a legitimate platform (a page inside
// github.com, a doc on docs.google.com), so the feed contains that platform's
// hostname. Blocking the whole domain would flag every real link and email
// from it. The allowlist wins.
function bgIsAllowlisted(host) {
  host = (host || "").toLowerCase();
  if (!host) return false;
  if (
    typeof GUARDIAN_ALLOWLIST !== "undefined" &&
    GUARDIAN_ALLOWLIST.some((d) => host === d || host.endsWith("." + d))
  ) {
    return true;
  }
  return (
    typeof GUARDIAN_ALLOWLIST_SUFFIXES !== "undefined" &&
    GUARDIAN_ALLOWLIST_SUFFIXES.some((s) => host.endsWith(s))
  );
}

// ---------------------------------------------------------------------------
// Blocklist tier. Content heuristics catch the loud scams; this catches the
// quiet, professional-looking phishing pages that have already been reported
// by security researchers. The feed is downloaded to this machine every few
// hours and checked locally: visited URLs never leave the computer.
// ---------------------------------------------------------------------------

const FEEDS = [
  // OpenPhish public feed (free ~300-URL phishing sample, refreshed several
  // times a day; openphish.com/feed.txt redirects here). The full feed is
  // commercial; PhishTank's free keyed database is the planned next source
  // (see TODO.md).
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
  // URLhaus by abuse.ch: currently-online malware URLs. Free, no key.
  "https://urlhaus.abuse.ch/downloads/text_online/"
];
const FEED_REFRESH_MINUTES = 6 * 60;

// A reserved .test host (RFC 6761: can never be a real website) used only
// by the local demo page test-pages/reported-scam-site.html to show the
// blocklist tier safely. Always treated as blocked; harmless in production.
const DEMO_BLOCKED_HOST = "guardian-demo-blocked-site.test";

// Hosts where one hostname fronts many unrelated tenants (shorteners, but also
// raw.githubusercontent.com and friends) live in GUARDIAN_PATH_MATCH_HOSTS in
// data/ad-networks.js and are matched by full URL path, never by hostname.

// Canonical form of a URL for path-level matching: origin + path, lowercased,
// no query, no fragment, no trailing slash.
function guardianNormalizeUrl(href) {
  try {
    const u = new URL(href);
    // Only the ORIGIN is lowercased. URL paths are case-sensitive, and short
    // links depend on that: bit.ly/AbC123 and bit.ly/abc123 are different
    // links, and folding them together let one reported link implicate an
    // unrelated one on the same shortener.
    return u.origin.toLowerCase() + u.pathname.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

let blockedHosts = null; // Set of hostnames (from the feeds)
let blockedUrls = null; // Set of normalized full URLs (shortener links)
let userBlocked = null; // Set of hostnames the person reported themselves

async function loadBlocklist() {
  // refreshBlocklist() fills blockedHosts/blockedUrls but not userBlocked, so
  // guard on all three; a check arriving right after a feed refresh would
  // otherwise hit userBlocked.has() while userBlocked is still null.
  if (blockedHosts && blockedUrls && userBlocked) return;
  const { feedCache, blocklistHosts, blocklistUrls, guardianUserBlocklist } =
    await chrome.storage.local.get([
      "feedCache",
      "blocklistHosts",
      "blocklistUrls",
      "guardianUserBlocklist"
    ]);
  // Rebuilt from the per-feed cache, so a feed that is currently down still
  // contributes its last good data. blocklistHosts/blocklistUrls are the old
  // single-blob format, read once so an existing install is not left
  // unprotected until its first refresh.
  if (!blockedHosts || !blockedUrls) {
    const hosts = new Set(blocklistHosts || []);
    const urls = new Set(blocklistUrls || []);
    for (const url of Object.keys(feedCache || {})) {
      const c = feedCache[url] || {};
      for (const h of c.hosts || []) hosts.add(h);
      for (const u of c.urls || []) if (u) urls.add(u);
    }
    if (!blockedHosts) {
      blockedHosts = hosts;
      blockedHosts.add(DEMO_BLOCKED_HOST);
    }
    if (!blockedUrls) blockedUrls = urls;
  }
  if (!userBlocked) userBlocked = new Set(guardianUserBlocklist || []);
}

// Is this page/link on the blocklist? Multi-tenant hosts match by full path;
// everything else matches by hostname. The person's own reported sites
// count too.
//
// The path-match test is a SUFFIX match, not a Set lookup: the feed lists
// raw.githubusercontent.com and gist.githubusercontent.com, and both must
// resolve to the githubusercontent.com entry. Before this, a hostname lookup
// missed the subdomain forms and the whole host was blocked wholesale.
// Returns WHO blocked this: "you" if the person reported it themselves,
// "feed" if it came from a public threat feed, "" if it is not blocked.
// The difference matters to what Guardian then says out loud: telling someone
// "security researchers reported this" about a site THEY reported five minutes
// ago is simply untrue.
async function blockSource(href, hostname) {
  await loadBlocklist();
  const host = (hostname || guardianHostOf(href)).toLowerCase();
  if (!host) return "";
  // The person's OWN report is checked first, and by suffix. Previously the
  // trusted list was consulted first, so reporting a site Guardian trusts did
  // nothing at all, and the match was exact, so reporting example.com left
  // login.example.com unprotected while the popup claimed the site was
  // reported. Their explicit decision outranks our defaults, and it is
  // reversible from the popup.
  if (guardianHostOnList(host, [...userBlocked])) return "you";
  if (bgIsAllowlisted(host)) return ""; // trusted domains are never blocked
  if (guardianHostOnList(host, GUARDIAN_PATH_MATCH_HOSTS)) {
    return blockedUrls.has(guardianNormalizeUrl(href)) ? "feed" : "";
  }
  return blockedHosts.has(host) ? "feed" : "";
}

async function isBlocked(href, hostname) {
  return !!(await blockSource(href, hostname));
}

function guardianHostOf(href) {
  try {
    return new URL(href).hostname.toLowerCase();
  } catch {
    return "";
  }
}

// Record one feed URL as either a blocked hostname or a blocked full path.
function ingestFeedUrl(raw, hosts, urls) {
  let host;
  try {
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    return; // skip malformed feed lines
  }
  // Never blocklist a trusted domain that merely HOSTS a reported page
  // (github.com/evil, docs.google.com/evil): that would flag the whole
  // legitimate platform. Keeps the stored blocklist clean too.
  if (bgIsAllowlisted(host)) return;

  // One hostname, many unrelated tenants: match the path, never the host.
  if (guardianHostOnList(host, GUARDIAN_PATH_MATCH_HOSTS)) {
    const norm = guardianNormalizeUrl(raw);
    if (norm) urls.push(norm);
    return;
  }

  // Shared ad/click infrastructure: the hostname identifies the NETWORK, not
  // the threat, so blocking it would take down every advert click on the web.
  // Record nothing at all.
  //
  // We deliberately do NOT follow the wrapper to its payload here. An ad URL's
  // query string carries the PUBLISHER page as often as the destination
  // (?url=<the site the ad appeared on>), so ingesting inner values would
  // blocklist innocent sites wholesale: one malvertising row naming a local
  // newspaper would put that newspaper behind a full-page scam warning. The
  // click chain is still followed at CHECK time (see checkUrlsEach), where a
  // wrong answer costs one unneeded lookup instead of a permanent stored
  // verdict about a site nobody reported.
  if (guardianHostOnList(host, GUARDIAN_AD_FRAME_HOSTS)) return;

  hosts.push(host);
}

async function fetchFeed(url) {
  const res = await fetch(url);
  if (!res.ok) return { hosts: [], urls: [] };
  const text = await res.text();
  const hosts = [];
  const urls = [];
  for (const line of text.split("\n")) {
    const raw = line.trim();
    if (!raw || raw.startsWith("#")) continue;
    ingestFeedUrl(raw, hosts, urls);
  }
  return { hosts, urls };
}

async function refreshBlocklist() {
  try {
    // Each feed is cached SEPARATELY with the time it last succeeded, and the
    // blocklist is the union of whatever is cached. Before this, the combined
    // list was rebuilt only from feeds that answered, so if one feed was down
    // its entries silently vanished until it came back - protection quietly
    // shrinking with nothing to show for it.
    const stored = await chrome.storage.local.get("feedCache");
    const cache = stored.feedCache || {};
    const status = {};
    const results = await Promise.allSettled(FEEDS.map(fetchFeed));

    FEEDS.forEach((url, i) => {
      const r = results[i];
      const got = r.status === "fulfilled" ? r.value : null;
      if (got && (got.hosts.length || got.urls.length)) {
        cache[url] = { hosts: got.hosts, urls: got.urls, at: Date.now() };
        status[url] = { ok: true, at: cache[url].at, count: got.hosts.length + got.urls.length };
      } else {
        const kept = cache[url];
        status[url] = {
          ok: false,
          at: kept ? kept.at : 0,
          count: kept ? kept.hosts.length + kept.urls.length : 0,
          error: r.status === "rejected" ? String(r.reason && r.reason.message || r.reason).slice(0, 120) : "empty response"
        };
      }
    });

    const hosts = new Set();
    const urls = new Set();
    for (const url of FEEDS) {
      const c = cache[url];
      if (!c) continue;
      for (const h of c.hosts) hosts.add(h);
      for (const u of c.urls) if (u) urls.add(u);
    }
    if (hosts.size === 0 && urls.size === 0) {
      await chrome.storage.local.set({ blocklistStatus: status });
      return; // nothing anywhere: keep whatever is already loaded
    }

    blockedHosts = hosts;
    blockedHosts.add(DEMO_BLOCKED_HOST);
    blockedUrls = urls;
    await chrome.storage.local.set({
      feedCache: cache,
      blocklistUpdated: Date.now(),
      blocklistStatus: status
    });
  } catch (e) {
    // offline etc: keep the previous list
  }
}

// Shared-hosting platforms that must never be trusted wholesale: a single
// entry would trust every portal/site hosted there, including phishing.
// Also used to purge any such entry stored by the pre-fix remember logic.
const NEVER_TRUST_WHOLESALE = new Set([
  "site.com", "my.site.com", "force.com", "wixsite.com", "weebly.com",
  "blogspot.com", "godaddysites.com", "pages.dev", "netlify.app",
  "vercel.app", "web.app", "firebaseapp.com", "github.io", "herokuapp.com",
  "glitch.me", "repl.co", "surge.sh"
]);

async function purgeBadUserAllowlistEntries() {
  const { guardianUserAllowlist } = await chrome.storage.local.get("guardianUserAllowlist");
  if (!Array.isArray(guardianUserAllowlist)) return;
  const cleaned = guardianUserAllowlist.filter((d) => !NEVER_TRUST_WHOLESALE.has(d));
  if (cleaned.length !== guardianUserAllowlist.length) {
    await chrome.storage.local.set({ guardianUserAllowlist: cleaned });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  refreshBlocklist();
  // Caught here rather than inside: a storage read that fails at install time
  // is not worth an unhandled rejection in the worker log, and the purge is a
  // tidy-up that the next install can just as well do.
  purgeBadUserAllowlistEntries().catch(() => {});
  chrome.alarms.create("guardian-refresh-blocklist", {
    periodInMinutes: FEED_REFRESH_MINUTES
  });
});
chrome.runtime.onStartup.addListener(refreshBlocklist);
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "guardian-refresh-blocklist") refreshBlocklist();
});

// ---------------------------------------------------------------------------
// On-device AI verdict via Chrome's built-in Prompt API (Gemini Nano,
// Chrome 138+). Runs here because the API is only exposed to extension
// contexts, not to ordinary web pages. Fully local; never load-bearing.
// ---------------------------------------------------------------------------

// The model is slow at times (its first use after a browser start loads
// gigabytes into memory), and Chrome kills this service worker after ~30s
// without extension-API activity — LanguageModel calls do not count. Left
// alone, a slow prompt means the worker dies mid-verdict, sendResponse never
// fires, and the popup waits forever. Two defenses: a keep-alive ping while
// the model works, and a hard timeout so callers ALWAYS get an answer and
// the heuristics take over.
const AI_TIMEOUT_MS = 25000;

async function aiVerdict(title, text, hostname, reputation, category) {
  const keepAlive = setInterval(() => {
    chrome.runtime.getPlatformInfo(() => {}); // resets the worker idle timer
  }, 20000);
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), AI_TIMEOUT_MS);
  try {
    if (typeof LanguageModel === "undefined") return "unknown";
    // Raced against the deadline as well. availability() and create() can both
    // stall while the model loads, and only prompt() was covered before, so a
    // slow start could still leave the caller waiting past the timeout.
    const availability = await Promise.race([
      LanguageModel.availability(),
      new Promise((resolve) => setTimeout(() => resolve("timeout"), AI_TIMEOUT_MS))
    ]);
    if (availability === "timeout") return "unknown";
    if (availability !== "available") {
      // Kick off the one-time model download in the background so future
      // checks work; answer from heuristics in the meantime.
      if (availability === "downloadable") LanguageModel.create().catch(() => {});
      return "unknown";
    }
    return await Promise.race([
      runAiPrompt(title, text, hostname, reputation, category, abort.signal),
      new Promise((resolve) => setTimeout(() => resolve("unknown"), AI_TIMEOUT_MS))
    ]);
  } catch (e) {
    return "unknown"; // model unavailable, aborted by the timeout, etc.
  } finally {
    clearTimeout(timer);
    clearInterval(keepAlive);
  }
}

async function runAiPrompt(title, text, hostname, reputation, category, signal) {
  // Extra guidance when the page is a software-download portal (Softonic
  // style): here the danger is deceptive, not textual, so tell the model
  // what to look for.
  const downloadNote =
    category === "download"
      ? " This is a software DOWNLOAD page. Treat it as a scam if it uses " +
        "fake or misleading 'Download' buttons, bundles adware/PUPs with the " +
        "installer, pushes a download manager instead of the real app, " +
        "offers cracked/pirated software, keygens or activation keys, or " +
        "impersonates an official vendor. A clearly official vendor or a " +
        "well-known open-source project download is SAFE."
      : "";
  let session = null;
  try {
    session = await LanguageModel.create({ signal });
    const out = await session.prompt(
      "You judge whether a web page is a scam (fake virus alert, fake " +
      "sign-in page, fake store, prize fraud, crypto fraud, tech support " +
      "fraud, deceptive software download)." + downloadNote + " Weigh the web " +
      "address heavily: scam pages very often sit on look-alike, brand-" +
      "stuffed, or throwaway domains, while a matching, reputable address is " +
      "reassuring. Reply with exactly one word: SCAM or SAFE.\n\nWeb address: " +
      (hostname || "(unknown)") +
      "\nWhat we know about the address: " + (reputation || "nothing") +
      "\nPage title: " + title + "\nPage text: " + text,
      { signal }
    );
    if (/^\s*SCAM/i.test(out)) return "scam";
    if (/^\s*SAFE/i.test(out)) return "safe";
    return "unknown";
  } finally {
    if (session) session.destroy();
  }
}

const DEFAULT_STATS = {
  totalBlocked: 0,
  bySource: { website: 0, email: 0 },
  byDay: {}, // "YYYY-MM-DD" -> count, last 30 days
  log: [] // newest first, capped at LOG_CAP
};
const LOG_CAP = 50;

async function getStats() {
  const { stats } = await chrome.storage.local.get("stats");
  if (!stats) return structuredClone(DEFAULT_STATS);
  // Merge with defaults so older stored shapes never break the popup
  return {
    ...structuredClone(DEFAULT_STATS),
    ...stats,
    bySource: { ...DEFAULT_STATS.bySource, ...(stats.bySource || {}) },
    byDay: { ...(stats.byDay || {}) }
  };
}

// Detections can land at the same moment from several frames. Each one reads
// the stats, changes them, and writes them back, so without serialising them
// the later write silently discards the earlier one's count. Every update is
// queued behind the last.
let guardianStatsChain = Promise.resolve();
function recordDetection(detection) {
  guardianStatsChain = guardianStatsChain
    .then(() => guardianApplyDetection(detection))
    .catch(() => {});
  return guardianStatsChain;
}

async function guardianApplyDetection({ source, label, reason }) {
  const stats = await getStats();
  stats.totalBlocked += 1;
  stats.bySource[source] = (stats.bySource[source] || 0) + 1;
  stats.log.unshift({ time: Date.now(), source, label, reason });
  stats.log = stats.log.slice(0, LOG_CAP);

  // Counted per day as well. The log is capped at 50 entries, so once someone
  // passes 50 the week's total silently started shrinking - the number went
  // DOWN the more Guardian did.
  const day = new Date().toISOString().slice(0, 10);
  stats.byDay = stats.byDay || {};
  stats.byDay[day] = (stats.byDay[day] || 0) + 1;
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  for (const d of Object.keys(stats.byDay)) {
    if (new Date(d + "T00:00:00Z").getTime() < cutoff) delete stats.byDay[d];
  }
  await chrome.storage.local.set({ stats });
  return stats.totalBlocked;
}

// Log a reported false positive and, for full-page website warnings, record
// that the person disagreed so the next warning on that host is gentler.
async function recordMistake(msg) {
  const store = await chrome.storage.local.get([
    "mistakes",
    "guardianDismissals",
    "guardianUserBlocklist"
  ]);
  const mistakes = store.mistakes || [];
  mistakes.unshift({
    time: Date.now(),
    hostname: msg.hostname || "",
    source: msg.source || "website",
    reason: msg.reason || ""
  });
  const set = { mistakes: mistakes.slice(0, 100) };

  // GRADUATED, not on/off. Dismissing used to write the host straight into
  // guardianUserAllowlist, which makes the content script bail out of
  // everything: ONE click and Guardian was permanently blind on that whole
  // hostname, with no way back. A dismissal now increments a counter that the
  // content script uses to SOFTEN the warning instead of switching detection
  // off:
  //   1 dismissal  -> the calm strip instead of the full-page takeover
  //   2 dismissals -> silent on that host (they have now said it twice)
  // Conclusive evidence is never softened, however often it is dismissed:
  // see guardianConclusive in content/page-scan.js.
  //
  // The FULL hostname is stored, never a truncated registrable guess: on a
  // shared platform (applefcu.my.site.com) truncating to site.com would
  // silence millions of unrelated portals, including phishing.
  if (msg.remember && msg.hostname) {
    const host = msg.hostname.toLowerCase();
    const counts = store.guardianDismissals || {};
    counts[host] = Math.min((counts[host] || 0) + (msg.strong ? 2 : 1), 2);
    set.guardianDismissals = counts;

    // UN-REPORT. The two buttons have to be true opposites, or a person can
    // get stuck: reporting a site adds it to their own blocklist, and nothing
    // ever took it back out. Guardian then warned on that site forever, and
    // because the warning did not say WHO reported it, it looked like an
    // outside verdict the person could not argue with. Saying "this is not a
    // scam" now withdraws their own earlier report as well.
    const reported = store.guardianUserBlocklist || [];
    const keep = reported.filter((d) => !(host === d || host.endsWith("." + d)));
    if (keep.length !== reported.length) {
      set.guardianUserBlocklist = keep;
      if (userBlocked) {
        for (const d of reported) {
          if (host === d || host.endsWith("." + d)) userBlocked.delete(d);
        }
      }
    }
  }
  await chrome.storage.local.set(set);
}

// Remember that the person corrected a download-ad neutralization on this
// host, so the feature stays quiet there. Deliberately a different store from
// guardianUserAllowlist: this must never disable scam detection.
async function adOptOut(hostname) {
  const { guardianAdOptOut } = await chrome.storage.local.get("guardianAdOptOut");
  const set = new Set(guardianAdOptOut || []);
  set.add(hostname);
  await chrome.storage.local.set({ guardianAdOptOut: [...set] });
}

// Add a person-reported scam host to their personal blocklist (and the live
// in-memory set) so it is blocked right away. There is no shared community
// backend, so this protects this user; the popup separately offers to
// forward the report to a public database that does protect everyone.
async function reportScam(hostname) {
  const host = hostname.toLowerCase();
  const store = await chrome.storage.local.get([
    "guardianUserBlocklist",
    "guardianDismissals",
    "guardianUserAllowlist"
  ]);
  const set = new Set(store.guardianUserBlocklist || []);
  set.add(host);
  const write = { guardianUserBlocklist: [...set] };

  // Reporting a scam is how a person TAKES BACK a previous "this is not a
  // scam". Without this the old answer wins: the warning stays softened or
  // silent, the person presses Report, and nothing visibly changes. Clear
  // both the dismissal counter and the legacy trusted entry for this host.
  const counts = store.guardianDismissals || {};
  let changed = false;
  for (const h of Object.keys(counts)) {
    if (host === h || host.endsWith("." + h)) { delete counts[h]; changed = true; }
  }
  if (changed) write.guardianDismissals = counts;

  const ua = store.guardianUserAllowlist || [];
  const keep = ua.filter((d) => !(host === d || host.endsWith("." + d)));
  if (keep.length !== ua.length) write.guardianUserAllowlist = keep;

  await chrome.storage.local.set(write);
  if (userBlocked) userBlocked.add(host);
}

// Take back a "this is not a scam" for ONE host, so a warning silenced by a
// mis-click can be brought back. There was previously no way back at all.
async function withdrawReport(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host) return;
  const store = await chrome.storage.local.get(["guardianUserBlocklist", "mistakes"]);
  const keep = (store.guardianUserBlocklist || []).filter(
    (d) => !(host === d || host.endsWith("." + d))
  );
  const mistakes = store.mistakes || [];
  mistakes.unshift({
    time: Date.now(),
    hostname: host,
    source: "withdrawn-report",
    reason: "the person withdrew their own report"
  });
  await chrome.storage.local.set({
    guardianUserBlocklist: keep,
    mistakes: mistakes.slice(0, 100)
  });
  if (userBlocked) {
    for (const d of [...userBlocked]) {
      if (host === d || host.endsWith("." + d)) userBlocked.delete(d);
    }
  }
}

async function clearDismissal(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host) return;
  const store = await chrome.storage.local.get([
    "guardianDismissals",
    "guardianUserAllowlist"
  ]);
  const counts = store.guardianDismissals || {};
  for (const h of Object.keys(counts)) {
    if (host === h || host.endsWith("." + h)) delete counts[h];
  }
  const ua = (store.guardianUserAllowlist || []).filter(
    (d) => !(host === d || host.endsWith("." + d))
  );
  await chrome.storage.local.set({
    guardianDismissals: counts,
    guardianUserAllowlist: ua
  });
}

// Tabs whose TOP frame has classified itself as a software-download portal,
// mapped to that frame's origin. Lets an advert frame that appears after the
// one-shot broadcast arm itself. Dropped when the tab closes; a navigation to
// a different site is handled by the origin having to match.
const portalTabs = new Map();
chrome.tabs.onRemoved.addListener((tabId) => {
  portalTabs.delete(tabId);
  chrome.storage.session.remove("portal:" + tabId).catch(() => {});
});

// Mirrored into session storage because this worker is evicted after ~30s of
// inactivity, which is shorter than the time a person spends reading a page.
function rememberPortal(tabId, origin) {
  portalTabs.set(tabId, origin);
  try {
    chrome.storage.session.set({ ["portal:" + tabId]: origin }).catch(() => {});
  } catch (e) {
    // session storage unavailable: the in-memory map still covers this session
  }
}

async function portalOriginFor(tabId) {
  const inMemory = portalTabs.get(tabId);
  if (inMemory) return inMemory;
  try {
    const s = await chrome.storage.session.get("portal:" + tabId);
    const origin = s["portal:" + tabId] || "";
    if (origin) portalTabs.set(tabId, origin); // repopulate after eviction
    return origin;
  } catch (e) {
    return "";
  }
}

function notify(source, reason) {
  const title =
    source === "email"
      ? guardianT("notif_title_email")
      : guardianT("notif_title_site");
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title,
    message: reason,
    priority: 2
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "checkUrl") {
    // isBlocked uses the explicit hostname when given (a demo-override from a
    // local test page) and otherwise derives it from the URL. Either way it
    // checks the person's own reported sites, shortener paths, and the feeds.
    blockSource(msg.href, msg.hostname || "")
      .then((source) => sendResponse({ blocked: !!source, source }))
      .catch(() => sendResponse({ blocked: false, source: "" }));
    return true; // async response
  }

  // On-device AI verdict, used by the content scripts (borderline pages)
  // and the popup's "Is this a scam?" button. Now given the web address and
  // a plain-language summary of what is locally known about it.
  if (msg.type === "aiCheck") {
    aiVerdict(
      String(msg.title || "").slice(0, 200),
      String(msg.text || "").slice(0, 3000),
      String(msg.hostname || ""),
      String(msg.reputation || ""),
      String(msg.category || "")
    )
      .then((verdict) => sendResponse({ verdict }))
      .catch(() => sendResponse({ verdict: "unknown" }));
    return true; // async response
  }

  // Used by the Gmail scanner: is any link in an email on the blocklist?
  // Links are checked as full URLs so shortener links match by path.
  if (msg.type === "checkHosts") {
    loadBlocklist().then(async () => {
      const urls = Array.isArray(msg.urls) ? msg.urls : [];
      let blockedHost = null;
      for (const u of urls) {
        if (await isBlocked(u, "")) {
          blockedHost = guardianHostOf(u);
          break;
        }
      }
      sendResponse({ blockedHost });
    }).catch(() => sendResponse({ blockedHost: null }));
    return true; // async response
  }

  // Which of these specific URLs are on the blocklist? Used to neutralize
  // individual bad download-ad buttons without touching the rest of the page.
  //
  // Each URL is followed through its click-tracker hops before being judged.
  // An ad click-through looks clean at its first hop and carries the real
  // destination in a query parameter, so checking only the literal href never
  // consults the payload host that a malware feed actually lists. Reports the
  // ORIGINAL url as bad so the caller can match it back to its element.
  if (msg.type === "checkUrlsEach") {
    loadBlocklist().then(async () => {
      const urls = Array.isArray(msg.urls) ? msg.urls : [];
      const bad = [];
      const badHosts = []; // parallel to bad: the hop that actually matched
      for (const u of urls) {
        const hops = guardianUnwrapClick(u);
        for (const hop of hops.length ? hops : [u]) {
          // A known-good download host is never judged, at any hop.
          if (guardianHostOnList(guardianHostOf(hop), GUARDIAN_DOWNLOAD_SAFE_HOSTS)) {
            continue;
          }
          if (await isBlocked(hop, "")) {
            bad.push(u);
            // The caller needs the ORIGINAL url to match it back to an
            // element, but must never NAME it to the person: a link shim like
            // l.facebook.com/l.php?u=<bad> would otherwise be announced as
            // "l.facebook.com has been reported as a scam".
            badHosts.push(guardianHostOf(hop));
            break;
          }
        }
      }
      sendResponse({ bad, badHosts });
    }).catch(() => sendResponse({ bad: [], badHosts: [] }));
    return true; // async response
  }

  // The top frame has classified itself as a software-download portal. Tell
  // every frame in the tab, so the ad-frame agents know they may act. Only a
  // top frame may arm, and the origin is taken from the SENDER, never from the
  // message, so a sub-frame cannot arm agents on someone else's behalf.
  // The ad-frame agents cannot read the shield setting or the per-site opt-out
  // themselves (they return before the storage read), so the worker re-checks
  // both here. Otherwise a frame armed by a stale top frame would keep acting
  // after the person switched the feature off.
  if (msg.type === "downloadPortal") {
    if (sender.tab && sender.tab.id !== undefined && sender.frameId === 0) {
      const tabId = sender.tab.id;
      const origin = sender.origin || "";
      chrome.storage.local
        .get(["guardianAdShield", "guardianAdOptOut"])
        .then((s) => {
          if (s.guardianAdShield === false) return;
          const host = guardianHostOf(origin);
          const opt = s.guardianAdOptOut || [];
          if (host && opt.some((d) => host === d || host.endsWith("." + d))) return;
          // Remembered so an advert frame that loads or refreshes AFTER this
          // one-shot broadcast can still ask (see portalStatus). Keyed to the
          // top frame's own origin, which the worker takes from the sender and
          // never from the message.
          rememberPortal(tabId, origin);
          chrome.tabs
            .sendMessage(tabId, { type: "guardianDownloadPortal", topOrigin: origin })
            .catch(() => {});
        })
        .catch(() => {});
    }
    return; // sync, no response
  }

  // An advert frame asking whether the page around it is a download portal.
  // The answer is the origin the TOP frame reported, so a frame cannot arm
  // itself by claiming to be somewhere it is not: it must already know the
  // real top origin to make use of the answer.
  if (msg.type === "portalStatus") {
    const tabId = sender.tab && sender.tab.id;
    if (tabId === undefined) {
      sendResponse({ topOrigin: "" });
      return;
    }
    // Re-checks the shield and the opt-out exactly as the downloadPortal
    // relay does, and reads through chrome.storage.session because this
    // worker is evicted while the person reads the page: the in-memory Map
    // would be empty for precisely the late ad-frame refresh this exists for.
    portalOriginFor(tabId)
      .then((origin) => {
        if (!origin) return sendResponse({ topOrigin: "" });
        return chrome.storage.local
          .get(["guardianAdShield", "guardianAdOptOut"])
          .then((s) => {
            if (s.guardianAdShield === false) return sendResponse({ topOrigin: "" });
            const host = guardianHostOf(origin);
            const opt = s.guardianAdOptOut || [];
            if (host && opt.some((d) => host === d || host.endsWith("." + d))) {
              return sendResponse({ topOrigin: "" });
            }
            sendResponse({ topOrigin: origin });
          });
      })
      .catch(() => sendResponse({ topOrigin: "" }));
    return true; // async response
  }

  // Restore every frame's neutralizations without recording an opt-out. Used
  // by the per-page cap's self-correction and by the popup's off switch, both
  // of which must be able to undo work done inside advert frames.
  if (msg.type === "adUndoAll") {
    if (sender.tab && sender.tab.id !== undefined) {
      chrome.tabs
        .sendMessage(sender.tab.id, { type: "guardianAdUndo" })
        .catch(() => {});
    }
    return; // sync, no response
  }

  // "This was the real download": undo a download-ad neutralization.
  //
  // This writes a SEPARATE guardianAdOptOut store, never guardianUserAllowlist.
  // The allowlist makes page-scan.js bail out of the whole content script, so
  // routing this through it would silently switch off ALL scam protection on
  // the site where the person was already having trouble. Correcting an advert
  // mistake must not cost them their scam protection.
  if (msg.type === "adOptOut" && msg.hostname) {
    adOptOut(String(msg.hostname).toLowerCase()).then(() => {
      if (sender.tab && sender.tab.id !== undefined) {
        chrome.tabs
          .sendMessage(sender.tab.id, { type: "guardianAdUndo" })
          .catch(() => {});
      }
      sendResponse({ ok: true });
    }).catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  // The person pressed "This is not a scam": record the false positive and,
  // when asked, remember the site so Guardian stops warning on it.
  if (msg.type === "reportMistake") {
    recordMistake(msg)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  // "This is not a scam after all": withdraw a report WITHOUT recording a
  // dismissal. Routing this through reportMistake also softened future
  // warnings, so undoing a report left the site quieter than a site that had
  // never been reported at all.
  if (msg.type === "withdrawReport" && msg.hostname) {
    withdrawReport(String(msg.hostname).toLowerCase()).then(() =>
      sendResponse({ ok: true })
    ).catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  // "Warn me here again": take back the dismissal for one host.
  if (msg.type === "clearDismissals") {
    clearDismissal(msg.hostname)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  // The person reported a scam Guardian missed. Add its hostname to their
  // personal blocklist so it is caught immediately from now on.
  if (msg.type === "reportScam" && msg.hostname) {
    reportScam(msg.hostname)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  if (msg.type === "scamDetected") {
    recordDetection({
      source: msg.source,
      label: msg.label,
      reason: msg.reason
    }).then(() => notify(msg.source, msg.reason));

    // If the detection came from inside an iframe (browser-in-the-browser
    // fake login windows), relay it to every frame in the tab so the top
    // frame shows the full-page overlay as well.
    //
    // A SUB-FRAME MAY ONLY ESCALATE IF IT HOLDS CREDENTIALS. Ad creatives are
    // sub-frames too, and scareware creatives ("Your PC is infected - call
    // now") score as scams on their own text. Without this guard, one such
    // advert takes over an entirely legitimate page and the banner names the
    // ad server instead of the site the person is actually on. The
    // browser-in-the-browser case this relay exists for always has a
    // credential input; an advert does not.
    const mayEscalate = sender.frameId === 0 || msg.credential === true;
    if (
      msg.source === "website" &&
      mayEscalate &&
      sender.tab &&
      sender.tab.id !== undefined
    ) {
      chrome.tabs
        .sendMessage(sender.tab.id, {
          type: "guardianShowOverlay",
          reason: msg.reason
        })
        .catch(() => {});
    }

    sendResponse({ ok: true });
    return; // sync response
  }

  if (msg.type === "closeTab" && sender.tab && sender.tab.id !== undefined) {
    chrome.tabs.remove(sender.tab.id);
    return;
  }
});
