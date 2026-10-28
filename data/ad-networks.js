// Evidence lists for the fake download-ad neutralizer, plus the small pure
// helpers that operate on them. Loaded by the page content scripts AND by the
// service worker (importScripts), so this file must stay dependency-free:
// no document, no window, no functions from detector.js.
//
// THE ONE RULE THIS FILE EXISTS TO ENFORCE:
// "the destination is on a different domain than the page" is NEVER, anywhere,
// a reason to disable a button. Domain difference is polarity-inverted under
// all_frames (inside an ad frame the ad link is same-domain while the site's
// OWN download link is cross-domain), and it breaks every open-source project
// that hosts its releases elsewhere, every printer-driver page, and every
// App Store badge. A button is only ever disabled on POSITIVE membership in
// one of the curated lists below, or on a threat-feed hit. Position evidence
// (which frame it sits in, whether the domain differs) may only ever DEMOTE.

// ---------------------------------------------------------------------------
// POSITION EVIDENCE ONLY. NEVER CONVICTS.
// Mainstream ad infrastructure. Seeing one of these tells us "this box is an
// advert slot", which is where we are ALLOWED to look. It never tells us the
// advert is bad: an honest advertiser buys these too. Nothing in this list may
// ever appear on the conviction side of a decision.
// RULES FOR ADDING: only real ad-serving/exchange infrastructure. If you would
// not be comfortable saying "an ad appeared here" on seeing this host, it does
// not belong.
// ---------------------------------------------------------------------------
const GUARDIAN_AD_FRAME_HOSTS = [
  "doubleclick.net", "googlesyndication.com", "googleadservices.com",
  "googletagservices.com", "2mdn.net", "adtrafficquality.google",
  "adnxs.com", "adsrvr.org", "rubiconproject.com", "magnite.com",
  "pubmatic.com", "openx.net", "indexww.com", "smartadserver.com",
  "adform.net", "sharethrough.com", "triplelift.com", "sovrn.com",
  "yieldmo.com", "gumgum.com", "33across.com", "criteo.com", "criteo.net",
  "teads.tv", "connatix.com", "media.net", "ad-delivery.net", "adfox.ru",
  "amazon-adsystem.com", "taboola.com", "outbrain.com", "mgid.com",
  "revcontent.com", "zergnet.com", "adskeeper.com", "trafficjunky.com",
  "btloader.com", "btmessage.com", "blockthrough.com", "softonicads.com"
];

// ---------------------------------------------------------------------------
// CONVICTION-GRADE. Deliberately narrow.
// A "Download" button pointing at one of these is not a real download on any
// legitimate site on the web. These are the popunder / push-notification /
// direct-link networks whose entire product is a deceptive click.
//
// EXCLUDED ON PURPOSE (do not add them, ever):
//  - doubleclick, googlesyndication, googleadservices, taboola, outbrain,
//    mgid, media.net, criteo, amazon-adsystem: mainstream inventory. Convicting
//    on these makes Guardian an ad blocker and neutralizes honest advertisers.
//  - go.skimresources.com, anrdoezrs.net, dpbolvw.net, tkqlhce.com,
//    click.linksynergy.com, awin1.com, shareasale.com, impact.com: legitimate
//    affiliate redirectors. Review sites route REAL vendor installers through
//    them, so convicting here would disable genuine downloads.
// RULES FOR ADDING: a wrong entry here causes a FALSE POSITIVE, so the bar is
// "this network's business model is the deceptive click itself".
// ---------------------------------------------------------------------------
const GUARDIAN_DECOY_NETWORKS = [
  "adsterra.com", "highperformanceformat.com", "profitabledisplaynetwork.com",
  "displayadmedia.com", "monetag.com", "propellerads.com", "propu.sh",
  "propeller-tracking.com", "onclkds.com", "omnatuor.com", "rtmark.net",
  "in-page-push.com", "inpagepush.com", "pushimg.com", "popads.net",
  "popcash.net", "adcash.com", "exoclick.com", "exdynsrv.com", "juicyads.com",
  "hilltopads.net", "hilltopads.com", "clickadu.com", "bidvertiser.com",
  "adnium.com", "adspyglass.com", "galaksion.com", "zeroredirect1.com",
  "trafficshop.com"
];

// ---------------------------------------------------------------------------
// EXEMPTIONS. A download pointing here is never touched.
// RULES FOR ADDING: BE GENEROUS. This list has the OPPOSITE risk asymmetry
// from allowlist.js: a wrong entry here causes only a MISS, never a false
// positive. When in doubt, add it.
// ---------------------------------------------------------------------------
const GUARDIAN_DOWNLOAD_SAFE_HOSTS = [
  // Code hosting and release mirrors
  "github.com", "githubusercontent.com", "sourceforge.net", "fosshub.com",
  "documentfoundation.org", "libreoffice.org", "kernel.org", "mozilla.org",
  "mozilla.net", "videolan.org", "apache.org", "gnu.org", "debian.org",
  "ubuntu.com", "linuxmint.com", "blender.org", "gimp.org",
  "chiark.greenend.org.uk", "python.org", "nodejs.org", "eclipse.org",
  "audacityteam.org", "notepad-plus-plus.org", "git-scm.com", "handbrake.fr",
  "rufus.ie", "keepassxc.org", "obsproject.com", "qbittorrent.org",
  "irfanview.com", "7-zip.org", "winscp.net", "putty.org",
  // App stores (image-only badges in clinic/church/credit-union footers)
  "apps.apple.com", "itunes.apple.com", "play.google.com",
  "apps.microsoft.com", "appgallery.huawei.com", "galaxystore.samsung.com",
  "f-droid.org", "flathub.org", "snapcraft.io",
  // Printer, scanner and hardware drivers a senior actually needs
  "c-wss.com", "canon.com", "canon-europe.com", "epson.com", "epson.net",
  "brother.com", "hp.com", "dell.com", "lenovo.com", "nvidia.com", "amd.com",
  "intel.com", "logitech.com", "realtek.com", "asus.com", "acer.com",
  "msi.com", "seagate.com", "westerndigital.com", "adobe.com", "oracle.com",
  "java.com", "vmware.com", "wacom.com", "garmin.com", "netgear.com",
  "tp-link.com", "dlink.com", "synology.com", "qnap.com",
  // Library, document and media services seniors are sent to
  "overdrive.com", "libbyapp.com", "documentcloud.org", "staticflickr.com",
  "vimeocdn.com", "sermonaudio.com", "subsplash.com"
];

// ---------------------------------------------------------------------------
// ONE HOSTNAME, MANY UNRELATED TENANTS. Match these by full URL path, never by
// hostname: blocking the hostname would punish every tenant because one is bad.
// (This list was formerly SHORTENER_HOSTS in background.js and only held URL
// shorteners. raw.githubusercontent.com alone is ~34% of the URLhaus feed, so
// hostname-matching it took down every raw GitHub file on the web.)
// RULES FOR ADDING: only hosts where ONE hostname fronts MANY unrelated
// tenants. NOTE: *.s3.amazonaws.com, *.cloudfront.net and
// *.blob.core.windows.net are deliberately ABSENT: there the SUBDOMAIN is the
// tenant, so ordinary hostname matching is already correct and precise.
// ---------------------------------------------------------------------------
const GUARDIAN_PATH_MATCH_HOSTS = [
  // URL shorteners and link-in-bio hosts (the original list)
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "lnk.ua", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at", "tiny.cc",
  "t.ly", "s.id", "bl.ink", "shorte.st", "adf.ly", "linktr.ee", "lnkd.in",
  // Code and file hosting: one host, millions of unrelated users
  "raw.githubusercontent.com", "objects.githubusercontent.com",
  "gist.githubusercontent.com", "codeload.github.com", "github.com",
  "gitlab.com", "bitbucket.org", "sourceforge.net",
  // Website-builder and cloud-storage CDNs
  "wsimg.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
  "drive.google.com", "docs.google.com", "sites.google.com",
  "dl.dropboxusercontent.com", "cdn.discordapp.com", "media.discordapp.net",
  "mediafire.com", "pastebin.com", "transfer.sh", "gofile.io",
  "files.wordpress.com", "static.wixstatic.com", "static1.squarespace.com",
  "archive.org", "onedrive.live.com", "1drv.ms", "box.com", "ipfs.io",
  "cloudflare-ipfs.com"
];

// ---------------------------------------------------------------------------
// Publisher-marked advert containers, for top-frame verification.
// EXACT attribute selectors ONLY. Never a substring test: "ad" is the last two
// letters of "downlo-ad", so [class*="ad"] matches .download-button, #download
// and .downloads-wrap, i.e. the container of the REAL download. It also
// matches header, headline, thread, read-more, shadow, gradient, badge,
// loading, load-more, upload, breadcrumb, adjacent and admin.
// test-pages/neutralizer-selftest.html asserts this whole collision set does
// not match, and that assertion is the enforcement mechanism.
// ---------------------------------------------------------------------------
const GUARDIAN_AD_SLOT_SELECTOR = [
  'iframe[id^="google_ads_iframe_"]',
  'iframe[name^="google_ads_iframe_"]',
  'iframe[id^="aswift_"]',
  "iframe[data-google-container-id]",
  'iframe[id^="adfox_"]',
  "ins.adsbygoogle",
  '[data-label="Advertisement" i]',
  '[aria-label="Advertisement" i]',
  '[data-meta="placeholder-slot"]',
  '[class~="adsbygoogle"]',
  '[class~="ad-slot"]',
  '[class~="ad-unit"]',
  '[class~="advertisement"]'
].join(", ");

// Query parameters that carry a real destination inside a click-tracker URL.
// "q" and "to" are deliberately excluded as far too generic.
const GUARDIAN_CLICK_PARAMS = [
  "adurl", "ad_url", "url", "u", "r", "dest", "destination", "redirect",
  "redirect_url", "redirecturl", "link", "out", "goto", "landing", "target"
];

// Download vocabulary. The /u flag is MANDATORY: without it JavaScript treats
// an accented letter as a non-word character, so ordinary Spanish and
// Portuguese prose ("se descargará automáticamente", "baixará") matches and
// every such page becomes a candidate. With \p{L} boundaries, "descargará"
// correctly does not match while "Descargar" does.
const GUARDIAN_DL_WORD_RE =
  /(^|[^\p{L}\p{N}])(downloads?|descargar|descarga|t[eé]l[eé]charger|herunterladen|scaricare?|baixar|downloaden|pobierz|indir|ladda\s?ner|last\s?ned|скачать|загрузить)($|[^\p{L}\p{N}])/iu;

// CJK has no word boundaries at all, so these are matched as substrings.
const GUARDIAN_DL_CJK = ["下载", "下載", "ダウンロード", "다운로드"];

// An executable handed to the user. This is what the feature is scoped to.
const GUARDIAN_INSTALLER_RE =
  /\.(exe|msi|dmg|pkg|apk|appimage|deb|rpm|scr|bat|cmd|jar)(\?|#|$)/i;

// Documents and media are OUT OF SCOPE IN CODE, not merely by scoring. On the
// long tail "Download" overwhelmingly means a doctor's new-patient forms, a
// church bulletin, a bus schedule, a library loan, or a grandchild's photo.
// .zip is deliberately treated as NOT an installer: far too commonly innocent.
const GUARDIAN_DOCUMENT_RE =
  /\.(pdf|docx?|xlsx?|pptx?|csv|ics|txt|rtf|jpe?g|png|gif|webp|svg|mp3|m4a|wav|mp4|mov|avi|mkv|epub|zip|rar|7z|tar|gz)(\?|#|$)/i;

// Suffix membership, matching guardianIsAllowlisted's semantics exactly:
// the host itself, or any subdomain of it.
function guardianHostOnList(host, list) {
  const h = (host || "").toLowerCase();
  if (!h || !list) return false;
  return list.some((d) => h === d || h.endsWith("." + d));
}

function guardianIsDownloadLabel(s) {
  const t = (s || "").trim();
  if (!t) return false;
  if (GUARDIAN_DL_WORD_RE.test(t)) return true;
  return GUARDIAN_DL_CJK.some((w) => t.includes(w));
}

// A click-tracker URL carries its real destination in a query parameter
// (adclick.g.doubleclick.net/pcs/click?adurl=<real destination>). Returns the
// literal URL plus every destination nested inside it, so a threat feed can
// be consulted about the payload instead of the clean-looking first hop.
// Returns [] for anything that is not http(s), including javascript: hrefs.
function guardianUnwrapClick(href, depth) {
  depth = depth || 0;
  let u;
  try {
    u = new URL(href);
  } catch (e) {
    return [];
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return [];
  const out = [u.href];
  if (depth >= 3) return out; // bounded: a cycle must not hang the worker
  for (const key of GUARDIAN_CLICK_PARAMS) {
    let raw;
    try {
      raw = u.searchParams.get(key); // already percent-decoded
    } catch (e) {
      continue;
    }
    if (!raw) continue;
    let cand = raw.trim();
    if (cand.startsWith("//")) cand = u.protocol + cand; // protocol-relative
    if (!/^https?:\/\//i.test(cand)) continue;
    for (const nested of guardianUnwrapClick(cand, depth + 1)) {
      if (!out.includes(nested)) out.push(nested);
    }
  }
  return out;
}
