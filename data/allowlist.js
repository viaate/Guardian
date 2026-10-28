// Reputable domains that Guardian NEVER flags. This is the core
// anti-false-positive guarantee: if the senior is on their real bank's
// site, nothing Guardian does can scare them off it.
// Matching is by registrable-domain suffix (see detector.js).
//
// RULES FOR ADDING TO THIS LIST:
// - Only the canonical domain of a major, well-known organization.
// - NEVER add user-content hosts (wixsite.com, weebly.com, blogspot.com,
//   godaddysites.com, sites.google.com) or URL shorteners: that is
//   exactly where phishing pages are hosted.
// - When unsure, leave it off. A missing legit site costs one warning at
//   most; a wrongly listed host blinds Guardian completely.

// Entire trusted TLDs: US government, military, and accredited schools.
const GUARDIAN_ALLOWLIST_SUFFIXES = [".gov", ".mil", ".edu"];

const GUARDIAN_ALLOWLIST = [
  // Search, mail, big tech
  "google.com", "gmail.com", "youtube.com", "bing.com", "duckduckgo.com",
  "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
  "microsoftonline.com", "windows.com", "skype.com", "apple.com",
  "icloud.com", "yahoo.com", "aol.com", "mozilla.org", "adobe.com",
  "dropbox.com", "github.com", "zoom.us", "calendly.com", "wikipedia.org",
  "wikimedia.org", "wikidata.org",
  // First-party brand infrastructure / CDN domains (not user-content hosts):
  // real assets of the brands above, so seeing the brand name in them is
  // expected, not impersonation.
  "facebook.net", "fbcdn.net", "apple-dns.net", "cdn-apple.com",
  "amazon-adsystem.com", "media-amazon.com", "ssl-images-amazon.com",
  "cloud.microsoft", "static.microsoft", "gstatic.com",

  // Social
  "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
  "twitter.com", "x.com", "linkedin.com", "reddit.com", "pinterest.com",
  "nextdoor.com", "goodreads.com",

  // Shopping and marketplaces
  "amazon.com", "primevideo.com", "audible.com", "zappos.com",
  "wholefoodsmarket.com",
  // Amazon international storefronts (real sites people sign in to)
  "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca", "amazon.fr",
  "amazon.it", "amazon.es", "amazon.in", "amazon.com.au", "amazon.com.br",
  "amazon.com.mx", "amazon.nl",
  "ebay.com", "etsy.com", "walmart.com",
  "target.com", "costco.com", "samsclub.com", "bjs.com", "homedepot.com",
  "lowes.com", "menards.com", "acehardware.com", "bestbuy.com",
  "macys.com", "kohls.com", "nordstrom.com", "jcpenney.com",
  "dillards.com", "belk.com", "tjx.com", "wayfair.com", "overstock.com",
  "ikea.com", "dickssportinggoods.com", "rei.com", "basspro.com",
  "cabelas.com", "tractorsupply.com", "michaels.com", "joann.com",
  "hobbylobby.com", "barnesandnoble.com", "staples.com", "officedepot.com",
  "petco.com", "petsmart.com", "chewy.com", "qvc.com", "hsn.com",
  "llbean.com", "landsend.com", "talbots.com", "chicos.com", "groupon.com",

  // Groceries
  "kroger.com", "safeway.com", "albertsons.com", "publix.com",
  "wegmans.com", "aldi.us", "traderjoes.com", "foodlion.com", "heb.com",
  "meijer.com", "sprouts.com", "dollargeneral.com", "dollartree.com",
  "instacart.com",

  // Banks and credit unions
  "chase.com", "bankofamerica.com", "bofa.com", "wellsfargo.com",
  "wellsfargoadvisors.com", "citi.com", "citibank.com", "capitalone.com",
  "usbank.com", "pnc.com", "truist.com", "tdbank.com", "53.com",
  "huntington.com", "regions.com", "keybank.com", "citizensbank.com",
  "mtb.com", "bmo.com", "santanderbank.com", "ally.com", "usaa.com",
  "navyfederal.org", "penfed.org", "becu.org", "chime.com", "sofi.com",
  "marcus.com",

  // Cards, credit, payments
  "discover.com", "americanexpress.com", "synchrony.com", "paypal.com",
  "venmo.com", "zellepay.com", "zelle.com", "cash.app", "stripe.com",
  "squareup.com", "wise.com", "westernunion.com", "moneygram.com",
  "equifax.com", "experian.com", "transunion.com",
  "annualcreditreport.com", "creditkarma.com", "nerdwallet.com",

  // Investing and taxes
  "schwab.com", "fidelity.com", "vanguard.com", "troweprice.com",
  "etrade.com", "morganstanley.com", "ml.com", "edwardjones.com",
  "ameriprise.com", "robinhood.com", "coinbase.com", "intuit.com",
  "turbotax.com", "quickbooks.com", "hrblock.com", "taxact.com",

  // Insurance and health
  "geico.com", "statefarm.com", "progressive.com", "allstate.com",
  "libertymutual.com", "farmers.com", "nationwide.com", "aetna.com",
  "cigna.com", "humana.com", "uhc.com", "unitedhealthcare.com",
  "anthem.com", "bcbs.com", "kaiserpermanente.org", "mychart.com",
  "cvs.com", "walgreens.com", "riteaid.com", "goodrx.com", "drugs.com",
  "webmd.com", "mayoclinic.org", "clevelandclinic.org",
  "hopkinsmedicine.org", "healthline.com", "23andme.com", "ancestry.com",

  // Phone, internet, TV
  "verizon.com", "att.com", "t-mobile.com", "xfinity.com", "comcast.com",
  "spectrum.com", "spectrum.net", "cox.com", "centurylink.com",
  "frontier.com", "dish.com", "directv.com", "consumercellular.com",
  "tracfone.com", "straighttalk.com",

  // Security vendors (their REAL sites; fake renewal bills impersonate
  // them constantly)
  "norton.com", "mcafee.com", "malwarebytes.com",

  // Streaming and entertainment
  "netflix.com", "hulu.com", "disneyplus.com", "spotify.com",
  "pandora.com", "siriusxm.com", "paramountplus.com", "peacocktv.com",
  "max.com", "tubitv.com", "pluto.tv", "roku.com", "sling.com",
  "imdb.com", "rottentomatoes.com", "fandango.com", "ticketmaster.com",
  "eventbrite.com", "pogo.com", "duolingo.com",

  // Travel
  "expedia.com", "booking.com", "hotels.com", "priceline.com",
  "kayak.com", "tripadvisor.com", "southwest.com", "delta.com",
  "united.com", "aa.com", "alaskaair.com", "jetblue.com",
  "allegiantair.com", "marriott.com", "hilton.com", "hyatt.com",
  "ihg.com", "wyndhamhotels.com", "choicehotels.com", "bestwestern.com",
  "airbnb.com", "vrbo.com", "amtrak.com", "greyhound.com", "hertz.com",
  "enterprise.com", "avis.com", "budget.com", "aaa.com", "uber.com",
  "lyft.com", "carnival.com", "royalcaribbean.com", "princess.com",
  "hollandamerica.com",

  // News, weather, sports
  "nytimes.com", "washingtonpost.com", "wsj.com", "usatoday.com",
  "cnn.com", "foxnews.com", "nbcnews.com", "cbsnews.com", "msnbc.com",
  "go.com", "npr.org", "bbc.com", "bbc.co.uk", "apnews.com",
  "reuters.com", "theguardian.com", "latimes.com", "chicagotribune.com",
  "nypost.com", "newsweek.com", "time.com", "theatlantic.com",
  "forbes.com", "bloomberg.com", "cnbc.com", "marketwatch.com",
  "barrons.com", "politico.com", "thehill.com", "axios.com",
  "weather.com", "accuweather.com", "wunderground.com", "espn.com",
  "mlb.com", "nfl.com", "nba.com", "nhl.com", "pgatour.com",

  // Food and restaurants
  "mcdonalds.com", "subway.com", "dominos.com", "pizzahut.com",
  "papajohns.com", "olivegarden.com", "crackerbarrel.com", "dennys.com",
  "ihop.com", "starbucks.com", "dunkindonuts.com", "panerabread.com",
  "chick-fil-a.com", "doordash.com", "ubereats.com", "grubhub.com",
  "allrecipes.com", "foodnetwork.com", "tasteofhome.com",
  "bettycrocker.com", "epicurious.com",

  // Home, jobs, local
  "zillow.com", "realtor.com", "redfin.com", "trulia.com",
  "apartments.com", "indeed.com", "glassdoor.com", "monster.com",
  "ziprecruiter.com", "yelp.com", "opentable.com", "angi.com",
  "thumbtack.com",

  // Shipping
  "usps.com", "ups.com", "fedex.com", "dhl.com",

  // Seniors, reference, faith, memory
  "aarp.org", "legacy.com", "findagrave.com", "newspapers.com",
  "britannica.com", "dictionary.com", "merriam-webster.com",
  "thesaurus.com", "rd.com", "people.com", "goodhousekeeping.com",
  "biblegateway.com", "bible.com",

  // Charities
  "redcross.org", "salvationarmyusa.org", "goodwill.org", "stjude.org",
  "unitedway.org", "habitat.org", "aspca.org", "humanesociety.org",
  "feedingamerica.org", "gofundme.com", "doctorswithoutborders.org",
  "worldwildlife.org", "cancer.org", "diabetes.org", "heart.org",
  "alz.org", "woundedwarriorproject.org", "dav.org",

  // More big tech / productivity / accounts people sign into
  "gmail.com", "protonmail.com", "proton.me", "zoho.com", "slack.com",
  "notion.so", "trello.com", "asana.com", "atlassian.com", "gitlab.com",
  "bitbucket.org", "stackoverflow.com", "wordpress.com", "wordpress.org",
  "cloudflare.com", "1password.com", "lastpass.com", "bitwarden.com",
  "dashlane.com", "docusign.com", "grammarly.com", "canva.com",
  "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.google.com",

  // More banks / credit unions / finance
  "fifththird.com", "firstrepublic.com", "comerica.com", "zionsbank.com",
  "associatedbank.com", "firstcitizens.com", "webster.com", "valley.com",
  "flagstar.com", "sofi.com", "varomoney.com", "current.com", "dave.com",
  "greenlight.com", "acorns.com", "betterment.com", "wealthfront.com",
  "creditonebank.com", "barclaycardus.com", "citizensbankonline.com",
  "suntrust.com", "bbt.com", "goldmansachs.com", "jpmorgan.com",
  "principal.com", "empower.com", "johnhancock.com", "prudential.com",
  "metlife.com", "newyorklife.com", "massmutual.com", "lincolnfinancial.com",
  "transamerica.com", "thrivent.com",

  // Insurance / health providers
  "libertymutual.com", "amfam.com", "erieinsurance.com", "thehartford.com",
  "travelers.com", "mercuryinsurance.com", "esurance.com", "healthcare.gov",
  "myaetna.com", "caremark.com", "expressscripts.com", "optum.com",
  "questdiagnostics.com", "labcorp.com",
  "teladoc.com", "aarpmedicareplans.com", "silverscript.com",

  // More telecom / utilities
  "boostmobile.com", "cricketwireless.com", "metrobyt-mobile.com",
  "metropcs.com", "visible.com", "mintmobile.com", "googlefi.com",
  "duke-energy.com", "pge.com", "coned.com", "nationalgrid.com",
  "dominionenergy.com", "xcelenergy.com", "aep.com", "firstenergycorp.com",

  // More travel / airlines / hotels
  "spirit.com", "frontier.com", "hawaiianairlines.com", "aircanada.com",
  "britishairways.com", "lufthansa.com", "airfrance.com", "klm.com",
  "emirates.com", "qatarairways.com", "ryanair.com", "easyjet.com",
  "accor.com", "radissonhotels.com", "motel6.com",
  "redroof.com", "laquinta.com", "expedia.com", "hotwire.com", "travelocity.com",
  "orbitz.com", "cheaptickets.com", "vacationsbymarriott.com",

  // More retail / groceries / pharmacies
  "sephora.com", "ulta.com", "gap.com", "oldnavy.com", "bananarepublic.com",
  "nike.com", "adidas.com", "underarmour.com", "footlocker.com", "asos.com",
  "shein.com", "temu.com", "wish.com", "aliexpress.com", "newegg.com",
  "bhphotovideo.com", "chewy.com", "1800flowers.com", "ftd.com",
  "harryanddavid.com", "williams-sonoma.com", "potterybarn.com",
  "crateandbarrel.com", "westelm.com", "bedbathandbeyond.com",
  "riteaid.com", "familydollar.com", "biglots.com", "fivebelow.com",
  "harristeeter.com", "winndixie.com", "giantfood.com", "stopandshop.com",
  "shoprite.com", "vons.com", "ralphs.com", "freshdirect.com", "gopuff.com",

  // More streaming / media / entertainment
  "primevideo.com", "appletv.com", "youtubetv.com", "philo.com",
  "crunchyroll.com", "twitch.tv", "vimeo.com", "soundcloud.com",
  "audible.com", "kindle.com", "goodreads.com", "audiobooks.com",
  "scribd.com", "steampowered.com", "epicgames.com", "playstation.com",
  "xbox.com", "nintendo.com", "aarp.org", "wordle.com",

  // Education / learning / kids-and-grandkids
  "khanacademy.org", "coursera.org", "udemy.com", "edx.org",
  "duolingo.com", "quizlet.com", "chegg.com", "canvas.instructure.com",
  "blackboard.com", "gradelink.com", "classdojo.com", "greatschools.org",
  "commonapp.org", "fafsa.gov", "collegeboard.org",

  // Government-adjacent / civic (beyond the .gov suffix rule)
  "usa.gov", "benefits.gov", "ready.gov", "vote.org", "aarp.org",
  "eldercare.acl.gov", "consumerfinance.gov", "ftc.gov",
  "reportfraud.ftc.gov", "identitytheft.gov", "annualcreditreport.com",

  // International majors people commonly use in the US
  "bbc.co.uk", "theguardian.com", "shopify.com", "wise.com", "revolut.com",
  "booking.com", "skyscanner.com", "airbnb.com", "tripadvisor.com",
  "spotify.com", "deezer.com", "samsung.com", "lg.com", "sony.com",
  "philips.com", "bosch.com", "ikea.com", "lego.com",

  // Brand-OWNED infrastructure / CDNs. These contain a brand name in the
  // hostname (so the impersonation check would otherwise flag them) but are
  // single-tenant, owned by that brand, and never host phishing. Do NOT add
  // multi-tenant hosts here (amazonaws.com, cloudfront.net, azureedge.net,
  // googleusercontent.com) - those DO host user content, including scams.
  "apple-dns.net", "cdn-apple.com", "apple-cloudkit.com", "mzstatic.com",
  "aaplimg.com", "amazon-adsystem.com", "media-amazon.com",
  "ssl-images-amazon.com", "images-amazon.com", "cloud.microsoft",
  "static.microsoft", "usercontent.microsoft", "msftauth.net", "msauth.net",
  "gstatic.com", "ggpht.com", "fbcdn.net"
];
