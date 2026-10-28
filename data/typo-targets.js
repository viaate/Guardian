// Popular-site names protected against typosquatting, IN ADDITION to
// data/allowlist.js and the brands in data/scam-phrases.js. Used ONLY as
// typosquat comparison targets.
//
// THIS IS NOT AN ALLOWLIST. Nothing here is trusted, and being on this list
// never stops Guardian from flagging a site. The only effect is that a
// hostname spelled almost like one of these names reads as a look-alike.
//
// RULES FOR ADDING:
// - Labels shorter than 8 characters are deliberately excluded. Short names
//   collide with real words, and the measurement below is what that floor buys.
// - No ordinary English words ('business', 'services'), and no infrastructure
//   nobody types ('amazonaws', 'googleapis'): each is a chance to collide with
//   a legitimate site and neither protects anyone.
// - Consumer brands shorter than 8 characters belong in data/allowlist.js,
//   which is already a typosquat target list as well as a trust list.
//
// MEASURED, against the popular-domain list ranked 3000-9000 (6000 real,
// legitimate sites), and against typosquat variants generated from popular
// names (omission, doubling, transposition, homoglyph, hyphen, missing dot):
//
//                          false positives      typosquats caught
//   before this list        14 / 6000 (0.23%)   2.1%
//   with this list          24 / 6000 (0.40%)   54.5%
//
// Every one of those false positives is a plain edit-distance match. Guardian
// has TWO thresholds, not one: 6 flags the page outright, and 4 raises the
// amber "might not be safe" strip. A near-miss against a name on THIS list is
// therefore scored +1, or +3 beside a login box, deliberately capped below 4
// so it can never raise either warning by itself (see
// guardianTypoTargetIsBroad in content/detector.js). It can still corroborate
// other evidence. Matches against the allowlist and the known brands keep
// their original higher weight.
//
// The high-confidence look-alike path (paypa1 -> paypal), which CAN flag a
// login page by itself, produced ZERO false positives across all 6000.
// Re-run test-pages/selftest-node.js and the measurement before changing the
// length floor or the scoring cap.
const GUARDIAN_TYPO_TARGETS = [
  "academia", "accenture", "ailawandorder", "airtable", "aljazeera",
  "altervista", "angelfire", "apachefriends", "apachelounge", "archlinux",
  "arstechnica", "autodesk", "automattic", "bandcamp", "bell-labs",
  "berkeley", "bigcartel", "bilibili", "billboard", "biomedcentral",
  "bizjournals", "blogspot", "bluehost", "bostonglobe", "brandbucket",
  "broadcom", "brookings", "businesswire", "buydomains", "buzzfeed",
  "buzzsprout", "cambridge", "chinadaily", "clinicaltrials", "codeberg",
  "colorado", "colorlib", "columbia", "complianz", "computerworld",
  "congress", "cookieadmin", "cookiedatabase", "crunchbase", "dailymail",
  "dailymotion", "deadline", "deloitte", "deviantart", "digitalocean",
  "digitaltrends", "directadmin", "domaintools", "dreamhost", "dribbble",
  "dropcatch", "e-recht24", "earthlink", "economist", "elegantthemes",
  "elsevier", "enable-javascript", "engadget", "entrepreneur", "euronews",
  "evernote", "expireddomains", "fastcompany", "federalreserve",
  "fedoraproject", "feedburner", "flaticon", "fliphtml5", "fontawesome",
  "foursquare", "france24", "fraunhofer", "freedesktop", "frontiersin",
  "gamespot", "generatepress", "geocities", "georgetown",
  "gesetze-im-internet", "getbootstrap", "getpocket", "globenewswire",
  "googleblog", "gotowebinar", "gravatar", "greenpeace", "guardian",
  "gutenberg", "hindustantimes", "hootsuite", "hostinger", "howstuffworks",
  "huffingtonpost", "huffpost", "hugedomains", "huggingface", "illinois",
  "imagemagick", "imageshack", "independent", "indianexpress", "indiatimes",
  "indiegogo", "instructables", "investing", "investopedia", "irishtimes",
  "ispconfig", "istockphoto", "jamanetwork", "jetbrains", "jimdofree",
  "jimdosite", "kadencewp", "kaspersky", "kickstarter", "laracasts",
  "launchpad", "lefigaro", "legislation", "letsencrypt", "lifehacker",
  "list-manage", "livejournal", "livescience", "logitech", "lonelyplanet",
  "macromedia", "magnific", "mailchimp", "mapquest", "mashable",
  "mastercard", "mastodon", "matterport", "mckinsey", "mediafire",
  "mediawiki", "medlineplus", "medscape", "memcached", "metmuseum",
  "mixcloud", "myshopify", "mystrikingly", "namebright", "namecheap",
  "netscape", "newscientist", "newyorker", "nobelprize", "northwestern",
  "nydailynews", "olympics", "openldap", "opensource", "openstreetmap",
  "ourworldindata", "over-blog", "ovhcloud", "panasonic", "parallels",
  "pastebin", "perplexity", "pewresearch", "photobucket", "postgresql",
  "prestashop", "princeton", "privacyshield", "prnewswire", "proofpoint",
  "qualtrics", "readthedocs", "repubblica", "researchgate", "rfc-editor",
  "rollingstone", "routledge", "salesforce", "sciencedaily",
  "sciencedirect", "sciencemag", "securityfocus", "shorturl",
  "shutterstock", "sketchfab", "slashdot", "slideshare", "smithsonianmag",
  "snapchat", "sourceforge", "speedtest", "spglobal", "springer",
  "squarespace", "squid-cache", "stackexchange", "stanford", "statcounter",
  "statista", "stumbleupon", "substack", "sueddeutsche", "surveymonkey",
  "symantec", "tandfonline", "teamviewer", "techcrunch", "techradar",
  "techtarget", "telegram", "telegraph", "termsfeed", "thedailybeast",
  "thelancet", "themeforest", "themegrill", "themeisle", "thenextweb",
  "theregister", "thetimes", "theverge", "thomsonreuters", "timeanddate",
  "timesofisrael", "tomshardware", "tradingview", "translate", "treasury",
  "trendmicro", "trustindex", "trustpilot", "typeform", "uchicago",
  "unsplash", "urldefense", "usembassy", "utoronto", "vanityfair",
  "venturebeat", "verisign", "videolan", "virginia", "virtualmin",
  "visualstudio", "vkontakte", "w3schools", "wampserver", "washington",
  "whitehouse", "wikibooks", "wikisource", "wiktionary", "wireshark",
  "withgoogle", "woocommerce", "worldbank", "worldcat", "wpengine",
  "wpguardian", "xiaohongshu", "xinhuanet", "ycombinator",
  "youtube-nocookie"
];
