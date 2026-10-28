// Guardian popup: stats plus the big "Is this a scam?" button.
// All user-facing text comes from data/strings.js (English/Spanish).

function startOfWeek() {
  const now = new Date();
  const day = now.getDay(); // 0 = Sunday
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate() - day);
  return start.getTime();
}

function localizeStatic() {
  // Without this a screen reader reads Spanish text with English pronunciation
  // rules, which is close to unintelligible.
  try {
    document.documentElement.lang = guardianLang();
  } catch (e) {
    // guardianLang unavailable: leave the document as-is
  }
  document.getElementById("label-blocked").textContent = guardianT("popup_blocked");
  document.getElementById("label-week").textContent = guardianT("popup_week");
  document.getElementById("label-websites").textContent = guardianT("popup_websites");
  document.getElementById("label-emails").textContent = guardianT("popup_emails");
  document.getElementById("check-hint").textContent = guardianT("popup_hint");
  // Say which build this is. Without it there is no way to tell a fix that
  // does not work from a fix that is not loaded - and Chrome does not reload
  // an unpacked extension on its own, so those look identical.
  let ver = "";
  try {
    ver = chrome.runtime.getManifest().version;
  } catch (e) {
    ver = "?";
  }
  document.getElementById("footer-note").textContent =
    guardianT("popup_footer") + "  v" + ver;
  document.getElementById("adshield-label").textContent =
    guardianT("popup_adshield_label");
  reportBtn.textContent = guardianT("popup_report");
  setButtonLabel();
}

function setButtonLabel() {
  const lines = guardianT("popup_button").split("|");
  checkBtn.textContent = "";
  lines.forEach((line, i) => {
    if (i > 0) checkBtn.appendChild(document.createElement("br"));
    checkBtn.appendChild(document.createTextNode(line));
  });
}

async function renderStats() {
  const { stats } = await chrome.storage.local.get("stats");
  const s = stats || { totalBlocked: 0, bySource: {}, log: [] };

  document.getElementById("total").textContent = s.totalBlocked || 0;
  document.getElementById("websites").textContent = (s.bySource && s.bySource.website) || 0;
  document.getElementById("emails").textContent = (s.bySource && s.bySource.email) || 0;

  // From the per-day counters, not the log: the log keeps only the newest 50
  // entries, so past 50 the week's total started going DOWN as Guardian did
  // more. Falls back to the log for installs that predate the counters.
  const weekStart = startOfWeek();
  let weekCount = 0;
  if (s.byDay && Object.keys(s.byDay).length) {
    for (const d of Object.keys(s.byDay)) {
      if (new Date(d + "T00:00:00").getTime() >= weekStart) weekCount += s.byDay[d];
    }
  } else {
    weekCount = (s.log || []).filter((e) => e.time >= weekStart).length;
  }
  document.getElementById("week").textContent = weekCount;
}

// ---------------------------------------------------------------------------
// The big button. Answers must be simple, confident, and non-technical.
// ---------------------------------------------------------------------------

const checkBtn = document.getElementById("check-btn");
const answerEl = document.getElementById("answer");

const ANSWER_STYLES = {
  scam: "answer-scam",
  ok: "answer-ok",
  careful: "answer-careful",
  signin: "answer-careful",
  remote: "answer-careful",
  links: "answer-careful",
  lookalike: "answer-careful",
  quiet: "answer-careful",
  cant: "answer-careful"
};

// Why the check could not be completed, when it could not. Kept because
// "We could not check this page" with no reason is a dead end for the person
// AND for anyone trying to fix it: a silent catch means nothing in the
// console either.
let guardianCantReason = "";
// Findings shown under the current answer, rebuilt for each press.
let guardianAnswerSignals = [];

// What Guardian actually noticed, in plain language.
function guardianBuildSignals(facts, result, opts) {
  const out = [];
  if (opts && opts.listed) {
    out.push(guardianT(opts.self ? "signal_reported_self" : "signal_reported"));
  }
  if (typeof guardianAddressSignals === "function" && facts && facts.hostname) {
    for (const t of guardianAddressSignals(facts.hostname)) out.push(t);
  }
  if (facts && facts.pwd) out.push(guardianT("signal_password"));
  if (facts && facts.pwd && facts.insecure) out.push(guardianT("signal_insecure"));
  for (const c of (result && result.categories) || []) {
    const key =
      typeof GUARDIAN_SIGNAL_KEYS !== "undefined" ? GUARDIAN_SIGNAL_KEYS[c] : null;
    if (key) out.push(guardianT(key));
  }
  return [...new Set(out)];
}

function showAnswer(kind, vars) {
  answerEl.className = ANSWER_STYLES[kind];
  answerEl.textContent = "";
  const main = document.createElement("div");
  main.className = "answer-main";
  main.textContent = guardianT("answer_" + kind + "_main", vars);
  const sub = document.createElement("div");
  sub.className = "answer-sub";
  sub.textContent = guardianT("answer_" + kind + "_sub", vars);
  answerEl.appendChild(main);
  answerEl.appendChild(sub);

  // The findings behind the answer. A bare "This is a SCAM" asks the person to
  // take a verdict on trust; heuristics are sometimes wrong, and someone who
  // can see WHY can weigh it for themselves.
  if (guardianAnswerSignals.length) {
    const list = document.createElement("ul");
    list.className = "answer-signals";
    guardianAnswerSignals.slice(0, 4).forEach((t) => {
      const li = document.createElement("li");
      li.textContent = t;
      list.appendChild(li);
    });
    answerEl.appendChild(list);
  }
  if (kind === "cant" && guardianCantReason) {
    const why = document.createElement("div");
    why.className = "answer-why";
    why.textContent = guardianCantReason;
    answerEl.appendChild(why);
  }
  answerEl.hidden = false;
  checkBtn.disabled = false;
  setButtonLabel();
}

// A page that gates its content behind third-party sign-in and is not a
// trusted site is exactly how fake-recruiter credential scams start. The
// person pressed this button because something felt off, so the button
// leans cautious: a real all-clear here would be wrong.
const SIGNIN_GATE_RE =
  /(sign in with google|continue with google|log ?in with google|sign in with microsoft|continue with microsoft|inicia sesión con google|continúa con google|iniciar sesión con google)/i;

// Judge where a page's links LEAD, not just how the page reads. Two sources of
// evidence, both high-confidence:
//   1. the reported-scam feed, checked locally in the service worker
//   2. a high-confidence look-alike address (paypa1.com, paypal.com.evil.net)
//
// Deliberately nothing weaker. Anything applied to eighty links at once has
// eighty chances to be wrong, so the ordinary edit-distance typosquat test -
// fine for judging one page's own address - is excluded here on purpose.
// See guardianLookalikeHost in content/detector.js.
async function checkPageLinks(links) {
  if (!Array.isArray(links) || !links.length) return null;

  const hostOf = (u) => {
    try {
      return new URL(u).hostname.toLowerCase();
    } catch (e) {
      return "";
    }
  };

  // 1. The threat feed. One round trip for the whole page.
  try {
    const resp = await chrome.runtime.sendMessage({
      type: "checkUrlsEach",
      urls: links.slice(0, 80)
    });
    if (resp && resp.bad && resp.bad.length) {
      // Name the hop that actually matched the feed, never the click wrapper
      // in front of it.
      const h = (resp.badHosts && resp.badHosts[0]) || hostOf(resp.bad[0]);
      if (h) return { kind: "links", vars: { host: h } };
    }
  } catch (e) {
    // worker asleep or unavailable: fall through to the local check
  }

  // 2. Local look-alike check. No network, no round trip.
  for (const u of links) {
    const h = hostOf(u);
    if (!h) continue;
    const target = guardianLookalikeHost(h);
    if (target) return { kind: "lookalike", vars: { host: h, target } };
  }
  return null;
}

// Read what is needed straight from the page, for tabs whose content script
// is missing or cut off.
//
// Deliberately a FUNCTION rather than re-injecting the script files: the files
// declare top-level consts, and running them a second time in a world that
// already has them throws a SyntaxError that kills the injection. A function
// gets a fresh scope every time. It collects facts only; the scoring happens
// here in the popup, which already loads the same engine.
// Ask the content script, if there is one. Never throws, never blocks an
// answer: resolves to null when nothing replies.
function guardianAskPage(tabId) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (!done) {
        done = true;
        resolve(v);
      }
    };
    setTimeout(() => finish(null), 400); // a dead tab never calls back
    try {
      chrome.tabs.sendMessage(tabId, { type: "guardianCollect" }, (r) => {
        void chrome.runtime.lastError;
        finish(r || null);
      });
    } catch (e) {
      finish(null);
    }
  });
}

async function guardianCollectDirect(tabId) {
  if (!chrome.scripting || !chrome.scripting.executeScript) {
    guardianCantReason = "the scripting permission is not active: reload Guardian in chrome://extensions";
    return null;
  }
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const links = [];
        const seen = new Set();
        for (const a of document.querySelectorAll("a[href]")) {
          if (!/^https?:$/.test(a.protocol)) continue;
          const u = a.href.split("#")[0];
          if (u.length > 2048 || seen.has(u)) continue;
          seen.add(u);
          links.push(u);
          if (links.length >= 80) break;
        }
        return {
          title: document.title,
          hostname: location.hostname,
          text: (document.body ? document.body.innerText : "").slice(0, 20000),
          pwd: !!document.querySelector('input[type="password"]'),
          email: !!document.querySelector(
            'input[type="email"], input[autocomplete="username"]'
          ),
          links
        };
      }
    });
    if (results && results[0] && results[0].result) return results[0].result;
    guardianCantReason = "the page returned nothing to check";
    return null;
  } catch (e) {
    // no permission for this tab, or a page Chrome forbids scripting on
    guardianCantReason = String((e && e.message) || e).slice(0, 140);
    return null;
  }
}

checkBtn.addEventListener("click", async () => {
  answerEl.hidden = true;
  checkBtn.disabled = true;
  checkBtn.textContent = guardianT("popup_checking");
  // Cleared for every press: otherwise the previous page's findings are shown
  // underneath this page's answer.
  guardianAnswerSignals = [];
  guardianCantReason = "";

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = (tab && tab.url) || "";
    if (!tab || tab.id === undefined || !/^(https?|file):/.test(url)) {
      guardianCantReason = !tab
        ? "no active tab"
        : tab.id === undefined
          ? "the tab has no id"
          : url
            ? "not an ordinary web page (" + url.split(":")[0] + ":)"
            : "the tab's address is not readable";
      return showAnswer("cant");
    }

    let host = "";
    try {
      host = new URL(url).hostname;
    } catch {}

    // Remote-control tool sites get the stop-and-think answer even before
    // the trusted-list check (Chrome Remote Desktop lives on google.com).
    if (
      typeof GUARDIAN_REMOTE_TOOLS !== "undefined" &&
      GUARDIAN_REMOTE_TOOLS.some((d) => host === d || host.endsWith("." + d))
    ) {
      return showAnswer("remote");
    }

    // A trusted site still gets ASKED before being called safe. Gmail is on
    // the trusted list, so this used to answer "looks OK" for mail.google.com
    // without once looking at the message on screen - which is the only thing
    // the person could possibly be asking about.
    if (guardianIsAllowlisted(host)) {
      const onPage = await guardianAskPage(tab.id);
      if (onPage && onPage.isScam) return showAnswer("scam");
      return showAnswer("ok");
    }

    // Has the person already told Guardian this site is fine? Noted, but NOT
    // acted on yet: answering "you said this is all right" instead of a
    // verdict answers a question nobody asked. It only matters if Guardian
    // would otherwise warn - see verdict() below.
    const quietHere = (await guardianSiteState(host)) === "quiet";

    // Guardian's answer, honouring an earlier "this is not a scam" - but only
    // where it changes anything. A clean page still answers "looks all right";
    // there is no reason to bring up an old click about a site that is fine.
    const WARNINGS = new Set(["scam", "careful", "signin", "links", "lookalike"]);
    const verdict = (kind, vars) =>
      showAnswer(quietHere && WARNINGS.has(kind) ? "quiet" : kind, vars);

    // Reported-scam blocklist.
    const bl = await chrome.runtime.sendMessage({ type: "checkUrl", href: url });
    if (bl && bl.blocked) return verdict("scam");

    // Read the page DIRECTLY. This used to ask the page's content script and
    // only fall back to reading the page when that produced nothing - which
    // meant any tab open before the extension was installed or reloaded got
    // "We could not check this page", because Chrome never re-injects into
    // existing tabs. Reading the page first has no such dependency: it works
    // on a tab that has been open for a week.
    const direct = await guardianCollectDirect(tab.id);

    // The content script is still worth asking, but only for the things it
    // alone knows: whether it already flagged this page, and whether this is a
    // remote-control tool. It is never required for an answer.
    const page = await guardianAskPage(tab.id);
    if (page && page.remoteTool) return showAnswer("remote");
    if (page && page.isScam) return verdict("scam");

    if (!direct && !page) {
      // Nothing could be read at all: a page Chrome forbids extensions on.
      // The address is still something.
      const look = guardianLookalikeHost(host);
      if (look) return verdict("lookalike", { host, target: look });
      return showAnswer("cant");
    }

    const facts = direct || {
      title: page.title,
      hostname: page.hostname,
      text: page.text,
      pwd: false,
      email: false,
      links: page.links || []
    };

    const result = guardianAnalyze({
      title: facts.title,
      text: facts.text,
      hostname: facts.hostname,
      hasPasswordField: facts.pwd,
      hasEmailInput: facts.email,
      insecureLogin: /^http:/.test(url) && facts.pwd,
      isEmail: false
    });
    if (result.isScam) return verdict("scam");

    let ai = null;
    try {
      ai = await chrome.runtime.sendMessage({
        type: "aiCheck",
        title: String(facts.title || "").slice(0, 200),
        text: String(facts.text || "").slice(0, 3000),
        hostname: facts.hostname,
        reputation: guardianReputationSummary(facts.hostname),
        category: ""
      });
    } catch (e) {
      // model unavailable: answer from the heuristics
    }
    if (ai && ai.verdict === "scam") return verdict("scam");

    // Where the page's links actually lead.
    const badLink = await checkPageLinks(facts.links || []);
    if (badLink) return verdict(badLink.kind, badLink.vars);

    if (SIGNIN_GATE_RE.test(facts.text || "")) return verdict("signin");
    if (ai && ai.verdict === "safe") return showAnswer("ok");
    return verdict(result.score >= 4 ? "careful" : "ok");
  } catch (e) {
    guardianCantReason = String((e && e.message) || e).slice(0, 140);
    showAnswer("cant");
  }
});

// ---------------------------------------------------------------------------
// Report this page as a scam. Adds the site to the person's own blocklist
// immediately (protects them going forward) and offers to forward it to a
// public database that protects everyone.
// ---------------------------------------------------------------------------

const reportBtn = document.getElementById("report-btn");
const reportDone = document.getElementById("report-done");

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

reportBtn.addEventListener("click", async () => {
  // Pending and failure states, so an action that silently failed cannot look
  // like one that worked. Guardian's whole job is telling someone the truth
  // about what happened.
  const label = reportBtn.textContent;
  reportBtn.disabled = true;
  reportBtn.textContent = guardianT("popup_working");
  try {
    await guardianDoReportAction();
  } catch (e) {
    reportBtn.disabled = false;
    reportBtn.textContent = label;
    reportDone.textContent = guardianT("popup_failed");
    reportDone.hidden = false;
  }
});

async function guardianDoReportAction() {
  const tab = await currentTab();
  let url = null;
  try {
    url = new URL((tab && tab.url) || "");
  } catch (e) {
    url = null;
  }
  // Only real web pages can be reported (not chrome://, the new-tab page,
  // extension pages, etc.). Tell the person instead of doing nothing.
  if (!url || !/^https?:$/.test(url.protocol)) {
    reportBtn.hidden = true;
    reportDone.textContent = guardianT("popup_report_none");
    reportDone.hidden = false;
    return;
  }
  const host = url.hostname;

  // Each state's button undoes exactly how that state was reached.
  if (siteState === "quiet") {
    await chrome.runtime.sendMessage({ type: "clearDismissals", hostname: host });
    reportBtn.hidden = true;
    quietNote.hidden = true;
    reportDone.textContent = guardianT("popup_quiet_undone", { host });
    reportDone.hidden = false;
    return;
  }

  if (siteState === "reported") {
    // withdrawReport, not reportMistake: recording a dismissal here left the
    // site quieter than one that was never reported at all.
    await chrome.runtime.sendMessage({ type: "withdrawReport", hostname: host });
    reportBtn.hidden = true;
    quietNote.hidden = true;
    reportDone.textContent = guardianT("popup_undo_done", { host });
    reportDone.hidden = false;
    return;
  }

  await chrome.runtime.sendMessage({ type: "reportScam", hostname: host });
  reportBtn.hidden = true;
  quietNote.hidden = true;
  reportDone.innerHTML = "";
  const line1 = document.createElement("div");
  line1.textContent = guardianT("popup_report_done", { host });
  const line2 = document.createElement("div");
  line2.style.marginTop = "6px";
  const link = document.createElement("a");
  link.href = "https://safebrowsing.google.com/safebrowsing/report_phish/?url=" +
    encodeURIComponent(tab.url);
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = guardianT("popup_report_google");
  line2.appendChild(link);
  reportDone.appendChild(line1);
  reportDone.appendChild(line2);
  reportDone.hidden = false;
}

// ---------------------------------------------------------------------------
// Fake download-button shield: an off switch, plus a visible count of the
// times the person pressed "This was the real download". The project's
// headline claim is a measured false-positive rate, so a new feature that can
// modify a page must not ship without a way to see when it gets it wrong.
// ---------------------------------------------------------------------------

const adShieldToggle = document.getElementById("adshield-toggle");
const adShieldNote = document.getElementById("adshield-note");

async function renderAdShield() {
  const { guardianAdShield, mistakes } = await chrome.storage.local.get([
    "guardianAdShield",
    "mistakes"
  ]);
  adShieldToggle.checked = guardianAdShield !== false;
  const wrong = (mistakes || []).filter((m) => m && m.source === "download-ad").length;
  adShieldNote.textContent = !wrong
    ? ""
    : wrong === 1
      ? guardianT("popup_adshield_note_one")
      : guardianT("popup_adshield_note", { n: wrong });
}

adShieldToggle.addEventListener("change", async () => {
  try {
    await chrome.storage.local.set({ guardianAdShield: adShieldToggle.checked });
  } catch (e) {
    // the setting did not save: put the tick back so it does not claim a
    // change that never happened
    adShieldToggle.checked = !adShieldToggle.checked;
    adShieldNote.textContent = guardianT("popup_failed");
    return;
  }
  // Make switching it OFF retroactive. Without this, buttons already covered
  // on the open page stay covered until a reload, so the switch looks broken.
  if (!adShieldToggle.checked) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.id !== undefined) {
        await chrome.tabs.sendMessage(tab.id, { type: "guardianAdUndo" });
      }
    } catch (e) {
      // no content script on this tab: nothing to undo
    }
  }
});

// ---------------------------------------------------------------------------
// ONE action at the bottom of the popup, matching what is actually true of the
// site you are on. There used to be two buttons that did the same job from the
// person's point of view ("I was wrong, this IS a scam" and "Warn me on this
// website again"), and no way at all to withdraw a report, because the only
// "This is not a scam" lived on the page warning - which is hidden precisely
// when you need it, since the warning is what was dismissed.
//
// Three states, one button each:
//   reported by you  -> "This is not a scam after all"  (withdraws the report)
//   dismissed by you -> "I was wrong, this IS a scam"   (starts warning again)
//   neither          -> "Report this page as a scam"
// ---------------------------------------------------------------------------

const quietNote = document.getElementById("quiet-note");
let siteState = "none";   // "reported" | "quiet" | "none"
let siteHost = "";

async function guardianSiteState(hostname) {
  const host = (hostname || "").toLowerCase();
  if (!host) return "none";
  const store = await chrome.storage.local.get([
    "guardianDismissals",
    "guardianUserAllowlist",
    "guardianUserBlocklist"
  ]);
  const hit = (h) => host === h || host.endsWith("." + h);
  if ((store.guardianUserBlocklist || []).some(hit)) return "reported";
  if (
    Object.keys(store.guardianDismissals || {}).some(hit) ||
    (store.guardianUserAllowlist || []).some(hit)
  ) {
    return "quiet";
  }
  return "none";
}

async function renderQuiet() {
  quietNote.hidden = true;
  const tab = await currentTab();
  try {
    siteHost = new URL((tab && tab.url) || "").hostname.toLowerCase();
  } catch (e) {
    siteHost = "";
  }
  siteState = await guardianSiteState(siteHost);

  if (siteState === "reported") {
    quietNote.textContent = guardianT("popup_reported_here", { host: siteHost });
    quietNote.hidden = false;
    reportBtn.textContent = guardianT("popup_report_undo");
  } else if (siteState === "quiet") {
    quietNote.textContent = guardianT("popup_quiet_here", { host: siteHost });
    quietNote.hidden = false;
    // Undo the dismissal, which is how this state was reached. Reporting it as
    // a scam is a different, stronger action, and it is what the button offers
    // once this site is back to normal.
    reportBtn.textContent = guardianT("popup_quiet_undo");
  } else {
    reportBtn.textContent = guardianT("popup_report");
  }
}

localizeStatic();
renderStats();
renderAdShield();
renderQuiet();
