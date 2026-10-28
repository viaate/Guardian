// Weighted scam phrase lists, grouped by category. All matching is done
// lowercase against page/email text. Weights are per CATEGORY (a category
// counts once no matter how many of its phrases match) so a wall of scam
// text does not need to be longer to score higher than a short one.
// Each category's reasonKey maps to a plain-language explanation in
// data/strings.js (English and Spanish).
// Phrases are bilingual: Spanish scam pages and emails target Spanish-
// speaking seniors with the same tricks, so both languages live in the
// same category and score identically.

const GUARDIAN_PHRASES = {
  techSupport: {
    weight: 4,
    reasonKey: "reason_techSupport",
    phrases: [
      "your computer has been locked",
      "your computer is infected",
      "your computer has been infected",
      "your device has been compromised",
      "your pc is infected",
      "windows defender security warning",
      "windows defender alert",
      "microsoft security alert",
      "apple security alert",
      "call microsoft support",
      "call apple support",
      "call windows support",
      "contact microsoft certified",
      "do not close this window",
      "do not shut down or restart",
      "do not ignore this critical alert",
      "your data is at risk",
      "viruses have been detected",
      "virus detected",
      "trojan detected",
      "spyware detected",
      "trojan_spyware",
      "error code 0x",
      "your ip address has been compromised",
      "your bank details and passwords are at risk",
      "windows has been blocked",
      "call now to fix",
      "toll free helpline",
      "certified technician",
      // Spanish
      "su computadora ha sido bloqueada",
      "su computadora está infectada",
      "su equipo ha sido infectado",
      "se han detectado virus",
      "virus detectado",
      "alerta de seguridad de microsoft",
      "alerta de seguridad de windows",
      "llame a soporte técnico",
      "no cierre esta ventana",
      "sus datos están en riesgo",
      // German
      "ihr computer wurde gesperrt",
      "ihr computer ist infiziert",
      "virus gefunden",
      "rufen sie den support an",
      "schließen sie dieses fenster nicht",
      // French
      "votre ordinateur a été bloqué",
      "votre ordinateur est infecté",
      "virus détecté",
      "appelez le support",
      "ne fermez pas cette fenêtre",
      // Italian
      "il tuo computer è stato bloccato",
      "il tuo computer è infetto",
      "virus rilevato",
      "chiama il supporto",
      "non chiudere questa finestra",
      // Portuguese
      "seu computador foi bloqueado",
      "seu computador está infectado",
      "vírus detectado",
      "ligue para o suporte",
      "não feche esta janela"
    ]
  },

  threats: {
    weight: 3,
    reasonKey: "reason_threats",
    phrases: [
      "warrant for your arrest",
      "warrant has been issued",
      "legal action will be taken",
      "you will be arrested",
      "your social security number has been suspended",
      "your ssn has been suspended",
      "suspicious activity on your social security",
      "final notice before legal proceedings",
      "law enforcement has been notified",
      "your benefits will be terminated",
      // Spanish
      "orden de arresto",
      "se tomarán acciones legales",
      "será arrestado",
      "su número de seguro social ha sido suspendido",
      "sus beneficios serán cancelados"
    ]
  },

  credentials: {
    weight: 2,
    reasonKey: "reason_credentials",
    phrases: [
      "verify your account immediately",
      "confirm your account information",
      "your account has been suspended",
      "your account has been locked",
      "your account will be closed",
      "unusual activity in your account",
      "unusual sign-in activity",
      "confirm your password",
      "update your payment information",
      "re-enter your billing information",
      "validate your account",
      "your account access has been limited",
      "change your password immediately",
      "change of password required",
      "password change required",
      "reset your password immediately",
      "password required immediately",
      "security breach",
      // Spanish
      "verifique su cuenta inmediatamente",
      "verifique su cuenta de inmediato",
      "su cuenta ha sido suspendida",
      "su cuenta ha sido bloqueada",
      "su cuenta será cerrada",
      "actividad inusual en su cuenta",
      "confirme su contraseña",
      "actualice su información de pago",
      "cambie su contraseña inmediatamente",
      // German
      "bestätigen sie ihr konto",
      "ihr konto wurde gesperrt",
      "ungewöhnliche aktivität in ihrem konto",
      "aktualisieren sie ihre zahlungsinformationen",
      // French
      "vérifiez votre compte immédiatement",
      "votre compte a été suspendu",
      "activité inhabituelle sur votre compte",
      "mettez à jour vos informations de paiement",
      // Italian
      "verifica il tuo account",
      "il tuo account è stato sospeso",
      "attività insolita sul tuo account",
      "aggiorna le tue informazioni di pagamento",
      // Spanish online-banking login prompts
      "ingrese su clave",
      "usuario y contraseña",
      "clave de acceso",
      "número de tarjeta",
      "banca en línea",
      "sucursal virtual",
      // Portuguese
      "verifique sua conta imediatamente",
      "sua conta foi suspensa",
      "atividade incomum na sua conta",
      "atualize suas informações de pagamento"
    ]
  },

  delivery: {
    weight: 2,
    reasonKey: "reason_delivery",
    phrases: [
      "your package could not be delivered",
      "your package is on hold",
      "delivery attempt failed",
      "unpaid customs fee",
      "pay a small fee to release",
      "redelivery fee",
      "schedule your redelivery",
      "shipping fee is required",
      "your parcel has been suspended",
      // Spanish
      "su paquete no pudo ser entregado",
      "su paquete está retenido",
      "el intento de entrega falló",
      "tarifa de reenvío",
      "pague una pequeña tarifa",
      "su paquete ha sido suspendido"
    ]
  },

  prizes: {
    weight: 3,
    reasonKey: "reason_prizes",
    phrases: [
      "you have won",
      "you've been selected",
      "congratulations you are today's lucky visitor",
      "claim your prize",
      "claim your reward",
      "you are the 1000000th visitor",
      "loyalty reward",
      "answer a few questions to claim",
      // Spanish
      "usted ha ganado",
      "ha sido seleccionado",
      "reclame su premio",
      "tarjeta de regalo gratis",
      "felicidades, usted es el visitante"
    ]
  },

  payment: {
    weight: 3,
    reasonKey: "reason_payment",
    phrases: [
      "pay with gift card",
      "pay using gift cards",
      "pay with an itunes gift card",
      "pay with a google play gift card",
      "purchase gift cards",
      "wire transfer immediately",
      "western union",
      "moneygram",
      "bitcoin payment",
      "pay in bitcoin",
      "cryptocurrency payment required",
      // Spanish
      "pague con tarjeta de regalo",
      "pague con tarjetas de regalo",
      "compre tarjetas de regalo",
      "transferencia bancaria inmediata",
      "pague con bitcoin"
    ]
  },

  giftCardAsk: {
    weight: 5,
    reasonKey: "reason_giftCardAsk",
    phrases: [
      "send me the numbers on the back",
      "send me the codes",
      "read me the numbers",
      "gift card codes",
      "scratch off the back",
      "scratch the back of the card",
      "take a photo of the card",
      "buy gift cards and send",
      // Spanish
      "envíeme los códigos",
      "los números de atrás de la tarjeta",
      "compre tarjetas de regalo y envíe",
      "una foto de la tarjeta",
      // German
      "kaufen sie geschenkkarten",
      "senden sie mir die codes",
      // French
      "achetez des cartes-cadeaux",
      "envoyez-moi les codes",
      // Italian
      "compra carte regalo",
      "inviami i codici",
      // Portuguese
      "compre cartões-presente",
      "envie-me os códigos"
    ]
  },

  cryptoSeed: {
    weight: 6,
    reasonKey: "reason_cryptoSeed",
    phrases: [
      "recovery phrase",
      "seed phrase",
      "secret recovery phrase",
      "mnemonic phrase",
      "12-word phrase",
      "24-word phrase",
      "12 word phrase",
      "24 word phrase",
      "enter your recovery phrase",
      "import your wallet",
      "validate your wallet",
      "sync your wallet",
      "restore your wallet",
      "wallet validation",
      "enter your private key",
      "your private key",
      // Spanish / other
      "frase de recuperación",
      "frase semilla",
      "clave privada"
    ]
  },

  renewalScam: {
    weight: 2,
    reasonKey: "reason_renewalScam",
    phrases: [
      "your subscription has been renewed",
      "has been auto-renewed",
      "auto renewal of your subscription",
      "your subscription will renew automatically",
      "to cancel the subscription call",
      "to cancel this charge",
      "renewal amount",
      "will be debited from your account",
      "your annual subscription",
      "invoice number",
      "geek squad protection",
      // Spanish
      "su suscripción ha sido renovada",
      "se ha renovado automáticamente",
      "para cancelar llame",
      "monto de renovación",
      "será debitado de su cuenta"
    ]
  },

  urgency: {
    weight: 1,
    reasonKey: "reason_urgency",
    phrases: [
      "immediate action required",
      "act now",
      "within 24 hours",
      "within the next 5 minutes",
      "before it's too late",
      "expires today",
      "your session will expire",
      "urgent response required",
      "time is running out",
      "offer expires in",
      "do this right away",
      // Spanish
      "acción inmediata requerida",
      "actúe ahora",
      "dentro de 24 horas",
      "antes de que sea tarde",
      "expira hoy",
      "su sesión expirará",
      "el tiempo se acaba",
      "hágalo de inmediato"
    ]
  }
};

// Login pages that scammers clone pixel-for-pixel. These phrases are the
// distinctive wording of the REAL sign-in screens (in both languages);
// when they appear next to a credential input on a domain that is not the
// real one, the page is a credential-stealing clone. Note the phrases are
// deliberately specific ("forgot email?" is Google's wording; normal sites
// say "forgot password?") so legit third-party login pages that merely
// OFFER "Continue with Google" never match.
const GUARDIAN_LOGIN_CLONES = [
  {
    display: "Google",
    homeDomain: "google.com",
    domains: ["google.com"],
    phrases: [
      "use your google account",
      "to continue to google",
      "not your computer? use guest mode",
      "forgot email?",
      // Spanish
      "usa tu cuenta de google",
      "¿olvidaste el correo electrónico?",
      "¿no es tu computadora? usa el modo de invitado"
    ]
  },
  {
    display: "Microsoft",
    homeDomain: "microsoft.com",
    domains: ["microsoft.com", "live.com", "outlook.com", "office.com"],
    phrases: [
      "use your microsoft account",
      "sign in to continue to outlook",
      "pick an account",
      "no account? create one",
      "email, phone, or skype",
      // Spanish
      "usa tu cuenta de microsoft",
      "¿no tienes una cuenta? crea una",
      "correo electrónico, teléfono o skype"
    ]
  }
];

// Brands commonly impersonated in phishing, with their real domains.
// If a page leans on one of these names but is NOT on the real domain
// and asks for credentials, that is a strong phishing signal.
const GUARDIAN_BRANDS = [
  { name: "paypal", display: "PayPal", domains: ["paypal.com"] },
  { name: "amazon", display: "Amazon", domains: ["amazon.com"] },
  { name: "apple", display: "Apple", domains: ["apple.com", "icloud.com"] },
  { name: "microsoft", display: "Microsoft", domains: ["microsoft.com", "live.com", "outlook.com", "office.com"] },
  { name: "netflix", display: "Netflix", domains: ["netflix.com"] },
  { name: "chase", display: "Chase", domains: ["chase.com"] },
  { name: "wells fargo", display: "Wells Fargo", domains: ["wellsfargo.com"] },
  { name: "bank of america", display: "Bank of America", domains: ["bankofamerica.com"] },
  { name: "citibank", display: "Citibank", domains: ["citi.com"] },
  { name: "capital one", display: "Capital One", domains: ["capitalone.com"] },
  { name: "usps", display: "USPS", domains: ["usps.com"] },
  { name: "fedex", display: "FedEx", domains: ["fedex.com"] },
  { name: "ups", display: "UPS", domains: ["ups.com"] },
  { name: "irs", display: "the IRS", domains: ["irs.gov"] },
  { name: "social security", display: "Social Security", domains: ["ssa.gov"] },
  { name: "medicare", display: "Medicare", domains: ["medicare.gov"] },
  { name: "ebay", display: "eBay", domains: ["ebay.com"] },
  { name: "facebook", display: "Facebook", domains: ["facebook.com"] },
  { name: "walmart", display: "Walmart", domains: ["walmart.com"] },
  { name: "costco", display: "Costco", domains: ["costco.com"] },
  { name: "norton", display: "Norton", domains: ["norton.com"] },
  { name: "mcafee", display: "McAfee", domains: ["mcafee.com"] },
  { name: "geek squad", display: "Geek Squad", domains: ["bestbuy.com"] },
  // Commonly impersonated in the wild (seen in live phishing feeds)
  { name: "roblox", display: "Roblox", domains: ["roblox.com"] },
  { name: "spotify", display: "Spotify", domains: ["spotify.com"] },
  { name: "steam", display: "Steam", domains: ["steampowered.com", "steamcommunity.com"] },
  { name: "discord", display: "Discord", domains: ["discord.com", "discord.gg"] },
  { name: "coinbase", display: "Coinbase", domains: ["coinbase.com"] },
  { name: "binance", display: "Binance", domains: ["binance.com"] },
  { name: "kraken", display: "Kraken", domains: ["kraken.com"] },
  { name: "metamask", display: "MetaMask", domains: ["metamask.io"] },
  { name: "ledger", display: "Ledger", domains: ["ledger.com"] },
  { name: "imtoken", display: "imToken", domains: ["token.im", "imtoken.com"] },
  { name: "trust wallet", display: "Trust Wallet", domains: ["trustwallet.com"] },
  { name: "trezor", display: "Trezor", domains: ["trezor.io"] },
  { name: "exodus", display: "Exodus", domains: ["exodus.com"] },
  { name: "phantom", display: "Phantom", domains: ["phantom.app"] },
  { name: "roku", display: "Roku", domains: ["roku.com"] },
  { name: "disney", display: "Disney", domains: ["disney.com", "disneyplus.com"] },
  { name: "dpd", display: "DPD", domains: ["dpd.com", "dpd.co.uk"] },
  { name: "correos", display: "Correos", domains: ["correos.es"] },
  { name: "bancolombia", display: "Bancolombia", domains: ["bancolombia.com"] },
  { name: "linkedin", display: "LinkedIn", domains: ["linkedin.com"] },
  { name: "instagram", display: "Instagram", domains: ["instagram.com"] },
  { name: "whatsapp", display: "WhatsApp", domains: ["whatsapp.com"] },
  { name: "docusign", display: "DocuSign", domains: ["docusign.com", "docusign.net"] },
  { name: "robinhood", display: "Robinhood", domains: ["robinhood.com"] },
  { name: "att", display: "AT&T", domains: ["att.com"] },
  { name: "twitter", display: "Twitter", domains: ["twitter.com", "x.com"] }
];

// Remote-control tools. All legitimate software, but tech-support
// scammers walk victims through installing them while on the phone, then
// take over the computer and the bank account. Guardian shows a calm
// stop-and-think caution on these sites instead of a scam warning.
const GUARDIAN_REMOTE_TOOLS = [
  "anydesk.com",
  "teamviewer.com",
  "ultraviewer.net",
  "rustdesk.com",
  "splashtop.com",
  "logmein.com",
  "getscreen.me",
  "remotedesktop.google.com"
];

// Wording that means the page is TEACHING about a scam rather than running
// one: a sheriff's fraud-alert page, a senior centre newsletter, a library
// class, a relative's blog post about what happened to their mother. Such a
// page quotes the scam's own words - "your computer is infected", a toll-free
// number - and so scores exactly like the thing it is warning about. The
// audience for those pages is the audience for Guardian, and covering a
// library's scam-awareness article with "STOP. This is a scam." is both wrong
// and the most embarrassing way to be wrong.
//
// These are phrases a scam cannot use without defeating itself: a page telling
// you to hang up, not to call, and that Microsoft will never phone you is not
// trying to get you to call. Measured against the scam texts in
// practice/scenarios.js, none reaches two of these; the awareness pages above
// carry three or more. Two are required, and see guardianAnalyze for the
// narrow circumstances in which they are allowed to count.
const GUARDIAN_TEACHING_MARKERS = [
  "hang up",
  "do not call",
  "don't call",
  "never call",
  "will never call",
  "never ask for",
  "will never ask",
  "do not give out",
  "never give out",
  "do not share your",
  "how to spot",
  "how to avoid",
  "how to protect",
  "protect yourself",
  "this is a scam",
  "these scams",
  "a common scam",
  "scam warning",
  "fraud alert",
  "report it to",
  "report this to",
  "if someone calls",
  "if you get a call",
  "scammers",
  "con artists",
  "was targeted",
  "were targeted",
  "do not respond",
  "delete the email",
  "block the number",
  // Spanish
  "cuelgue",
  "no llame",
  "nunca le pedirá",
  "nunca le pediremos",
  "cómo detectar",
  "protéjase",
  "es una estafa",
  "los estafadores",
  "denúncielo"
];
