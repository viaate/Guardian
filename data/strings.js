// All user-facing text, in English and Spanish. The language follows the
// browser's language automatically (a Spanish-speaking senior's Chrome is
// already in Spanish). Detection PHRASES live in scam-phrases.js and are
// bilingual there; this file is only what Guardian says to the person.
// Keep every string simple, confident, and non-technical.

const GUARDIAN_STRINGS = {
  en: {
    // Plain-language reasons
    reason_techSupport: "This page is pretending to be a virus warning. Real companies never show a phone number like this.",
    reason_threats: "This page is using threats to scare you. Real government agencies never threaten you like this online.",
    reason_credentials: "This page is trying to rush you into typing your password or personal information.",
    reason_delivery: "This looks like a fake package delivery notice. Delivery companies never ask for payment or passwords this way.",
    reason_prizes: "This looks like a fake prize page. If you did not enter a contest, you did not win one.",
    reason_payment: "This page is asking for gift cards or wire transfers. That is how scammers take money: no real business asks for these.",
    reason_giftCardAsk: "This is asking you to buy gift cards and share the codes. That is always a scam, no matter who it says it is from.",
    reason_renewalScam: "This looks like a fake bill. If you did not buy this, do not call the number on it: that phone call is the scam.",
    reason_cryptoSeed: "This page is asking for your crypto wallet's recovery phrase or private key. No real wallet ever asks for that on a website. Anyone who gets it can take all of your money.",
    reason_urgency: "This page is trying to rush you. Scammers use urgency so you do not stop and think.",
    reason_generic: "This page looks like a scam.",
    reason_clone: "This page is pretending to be a {brand} sign-in page. The real {brand} sign-in only happens on {domain}. Do not type anything here.",
    reason_typo: "This website's name is spelled almost like {target} but it is not the real site. Scammers use misspelled names to trick you.",
    reason_spoof: "This email pretends to be from {brand}, but it was really sent from {sender}. Real {brand} emails come from {domain}.",
    reason_link: "This email talks about your password or account, but its link goes to {host}, which does not belong to the sender. Do not click it.",
    reason_replyto: "This email is set up so that when you reply, your answer goes to {domain} instead of the real sender. Scammers do this to catch your reply.",
    reason_brand: "This page is pretending to be {brand} but it is not the real {brand} website. Do not type anything here.",
    reason_reported_site: "This website has been reported as a scam. Do not type anything here and do not call any phone number on it.",
    reason_reported_self: "You marked this website as a scam. Do not type anything here and do not call any phone number on it.",
    reason_insecure: "This page is asking for a password but it is not secure (no padlock). A real sign-in page is always secure. Do not type your password here.",
    reason_reported_email_link: "A link in this email goes to {host}, a website that has been reported as a scam. Do not click anything in this email.",
    reason_ai: "This page shows several signs of a scam. Do not type anything here and do not call any phone number on it.",
    different_address: "a different address",

    // Fake download-ad neutralizer.
    // adblock_badge makes the strongest claim and is reserved for a button
    // confirmed against a threat feed. Everything else uses adblock_badge_ad,
    // which is true, calm, and teaches the rule instead of accusing the page.
    adblock_badge: "Fake download blocked by Guardian",
    adblock_badge_ad: "This is an advert, not the download",
    adblock_title: "Guardian turned this button off. It is an advert, not this site's download.",
    adblock_dest: "This button goes to: {host}",
    adblock_undo: "This was the real download",

    // The fake-download shield's off switch, and the count of times the
    // person had to correct it.
    popup_report: "Report this page as a scam",
    popup_working: "Just a moment...",
    popup_failed: "That did not work. Please try again.",
    popup_reported_here: "You reported {host} as a scam, so Guardian warns you here.",
    popup_report_undo: "This is not a scam after all",
    popup_undo_done: "Thank you. Guardian will stop warning you about {host}.",
    popup_report_correct: "I was wrong, this IS a scam",
    popup_report_none: "There is no website open to report right now.",
    popup_report_done: "Thank you. Guardian will warn you about {host} from now on.",
    // Says what the link actually discloses. It opens Google's report form
    // with the full web address filled in, which is a disclosure the person
    // should be making knowingly.
    popup_report_google: "Also report it to Google (this sends the web address to Google)",
    popup_adshield_label: "Block fake “Download” buttons on download sites",
    popup_quiet_here: "You told Guardian that {host} is fine, so it is not warning you here.",
    popup_quiet_undo: "Warn me on this website again",
    popup_quiet_undone: "Done. Guardian will check {host} normally again.",
    popup_adshield_note: "Corrected {n} times by you.",
    popup_adshield_note_one: "Corrected once by you.",

    // "Is this a scam?" went deeper and found a bad LINK on an otherwise
    // ordinary-looking page.
    // Asked about a site the person has already told Guardian is fine. The
    // page warning respects that; the button ignoring it and declaring SCAM
    // reads as the dismissal being broken. Acknowledge it, and point at the
    // way to change their mind, which is directly below.
    answer_quiet_main: "You told Guardian this website is all right",
    answer_quiet_sub: "Guardian did find something here, but it is staying quiet because you said this website is fine. If you have changed your mind, press \"Warn me on this website again\" just below.",
    answer_links_main: "Careful: a link on this page is not safe",
    answer_links_sub: "The page itself looks ordinary, but one of its links goes to {host}, a website that has been reported as a scam. Do not click the links on this page.",
    answer_lookalike_main: "Careful: a link here is pretending to be {target}",
    answer_lookalike_sub: "The page itself looks ordinary, but one of its links goes to {host}. That address is spelled to look like {target} and is not the real site. Do not click it, and do not type your password there.",

    // Calm advice on software-download pages that carry adverts. Names no
    // button and changes nothing on the page.
    download_tip: "Guardian tip: on download sites like this one, the biggest, brightest \"Download\" buttons are usually adverts. The real download is normally a smaller link next to the program's name. If a file starts downloading on its own, do not open it.",

    // Soft caution strip (page MIGHT be a scam, not sure)
    caution_text: "Guardian: this page might not be safe. Be careful, and do not enter your password or personal information unless you are sure you trust it.",
    caution_dismiss: "OK, got it",
    // Shown instead of the full-page warning once the person has told
    // Guardian that this website is fine.
    caution_dismissed: "You told Guardian this website is all right, so this is only a reminder. Take care here: do not type your password, card number, or Social Security number unless you are sure.",
    caution_never: "Stop reminding me on this website",

    // Warning banner
    banner_heading_page: "STOP. This is a scam.",
    banner_heading_email: "This email looks like a scam",
    banner_close: "Close this page",
    banner_dismiss_page: "This is not a scam, show me the page",
    banner_dismiss_email: "Dismiss this warning",
    banner_footer: "Protected by Guardian",
    // The concrete findings behind a warning. Shown as a short list so the
    // person can judge for themselves instead of taking "several signs of a
    // scam" on faith. Each must be a plain fact, not a conclusion.
    signal_lookalike: "The web address is spelled to look like {target}, but it is not the real one",
    signal_reported: "Security researchers have reported this website as a scam",
    signal_reported_self: "You told Guardian this website is a scam",
    signal_tld: "The address ends in {tld}, an ending scam sites use a lot",
    signal_punycode: "The address uses foreign letters that look like English ones",
    signal_hyphens: "The address is padded with extra words and dashes",
    signal_digits: "The address has numbers mixed into the name",
    signal_password: "This page is asking for a password",
    signal_insecure: "The connection is not private (no padlock)",
    signal_virus: "It claims your computer has a virus",
    signal_threats: "It threatens you with arrest, fines, or losing your account",
    signal_credentials: "It wants your password or personal details",
    signal_delivery: "It pretends to be a missed delivery",
    signal_prizes: "It says you have won a prize",
    signal_payment: "It asks for gift cards, wire transfers, or crypto",
    signal_giftcard: "It asks you to buy gift cards and read out the codes",
    signal_bill: "It looks like a bill for something you did not buy",
    signal_crypto: "It asks for your crypto wallet recovery phrase",
    signal_urgency: "It is trying to rush you into acting fast",

    // Remote-control tool caution
    remote_heading: "Stop and think.",
    remote_text: "Is someone on the phone telling you to install this program? Hang up now. That is a scam. Real companies never call you and ask to control your computer.",
    remote_dismiss: "No one told me to open this, continue",

    // Notifications
    notif_title_site: "Guardian blocked a scam",
    notif_title_email: "Guardian flagged a scam email",

    // Popup
    popup_blocked: "scams blocked",
    popup_week: "this week",
    popup_websites: "websites",
    popup_emails: "emails",
    popup_button: "Is this|a scam?",
    popup_checking: "Checking...",
    popup_hint: "Not sure about the page you are on? Press the button.",
    // Accurate, not reassuring-sounding. Guardian DOES make network requests:
    // it downloads public lists of known scam sites every few hours. What it
    // never sends is anything about the person.
    popup_footer: "Checking happens on this computer. Guardian downloads public lists of known scam websites, but never sends the pages you visit, or anything about you.",
    answer_scam_main: "This is a SCAM.",
    answer_scam_sub: "Close this page. Do not type anything. Do not call any numbers.",
    answer_ok_main: "This page looks OK.",
    answer_ok_sub: "We found no signs of a scam. Still, never type a password after clicking a link someone sent you.",
    answer_careful_main: "Be careful.",
    answer_careful_sub: "This page shows warning signs. If you were not expecting it, close it.",
    answer_signin_main: "Do not sign in here.",
    answer_signin_sub: "This page asks you to sign in with Google. Only sign in on Google's own website. If someone sent you this link, close this page.",
    answer_remote_main: "Stop and think.",
    answer_remote_sub: "This program lets someone else control your computer. If anyone on the phone asked you to install it, hang up: that is a scam.",
    answer_cant_main: "We could not check this page.",
    answer_cant_sub: "Close it, open it again, and press the button once more."
  },

  es: {
    // Razones en lenguaje sencillo
    reason_techSupport: "Esta página finge ser un aviso de virus. Las empresas de verdad nunca muestran un número de teléfono así.",
    reason_threats: "Esta página usa amenazas para asustarlo. Las agencias del gobierno nunca amenazan así por internet.",
    reason_credentials: "Esta página lo está apurando para que escriba su contraseña o sus datos personales.",
    reason_delivery: "Esto parece un aviso falso de paquete. Las empresas de envíos nunca piden pagos ni contraseñas de esta manera.",
    reason_prizes: "Esto parece un premio falso. Si usted no participó en un sorteo, no ganó ningún premio.",
    reason_payment: "Esta página pide tarjetas de regalo o transferencias. Así roban el dinero los estafadores: ninguna empresa de verdad pide eso.",
    reason_giftCardAsk: "Le están pidiendo comprar tarjetas de regalo y compartir los códigos. Eso siempre es una estafa, sin importar quién lo pida.",
    reason_renewalScam: "Esto parece una factura falsa. Si usted no compró esto, no llame al número que aparece: esa llamada es la estafa.",
    reason_cryptoSeed: "Esta página pide la frase de recuperación o la clave privada de su billetera cripto. Ninguna billetera real pide eso en un sitio web. Quien la obtenga puede robarle todo su dinero.",
    reason_urgency: "Esta página lo está apurando. Los estafadores usan la prisa para que usted no se detenga a pensar.",
    reason_generic: "Esta página parece una estafa.",
    reason_clone: "Esta página finge ser la página para iniciar sesión de {brand}. La verdadera solo existe en {domain}. No escriba nada aquí.",
    reason_typo: "El nombre de este sitio se parece mucho a {target}, pero no es el sitio verdadero. Los estafadores usan nombres mal escritos para engañar.",
    reason_spoof: "Este correo finge ser de {brand}, pero en realidad fue enviado desde {sender}. Los correos verdaderos de {brand} vienen de {domain}.",
    reason_link: "Este correo habla de su contraseña o de su cuenta, pero su enlace lleva a {host}, que no pertenece al remitente. No haga clic.",
    reason_replyto: "Este correo está configurado para que, cuando usted responda, su respuesta vaya a {domain} en lugar del remitente real. Los estafadores hacen esto para atrapar su respuesta.",
    reason_brand: "Esta página finge ser {brand}, pero no es el sitio verdadero de {brand}. No escriba nada aquí.",
    reason_reported_site: "Este sitio web fue reportado como una estafa. No escriba nada aquí y no llame a ningún número que aparezca.",
    reason_reported_self: "Usted marcó este sitio como una estafa. No escriba nada aquí y no llame a ningún número que aparezca.",
    reason_insecure: "Esta página pide una contraseña pero no es segura (sin candado). Una página de inicio de sesión real siempre es segura. No escriba su contraseña aquí.",
    reason_reported_email_link: "Un enlace de este correo lleva a {host}, un sitio reportado como estafa. No haga clic en nada de este correo.",
    reason_ai: "Esta página muestra varias señales de estafa. No escriba nada aquí y no llame a ningún número.",
    different_address: "otra dirección",

    // Insignia del neutralizador de anuncios de descarga falsos
    adblock_badge: "Descarga falsa bloqueada por Guardian",
    adblock_badge_ad: "Esto es un anuncio, no la descarga",
    adblock_title: "Guardian desactivó este botón. Es un anuncio, no la descarga de este sitio.",
    adblock_dest: "Este botón lleva a: {host}",
    adblock_undo: "Esta era la descarga real",

    // Interruptor del escudo de descargas falsas
    popup_report: "Reportar esta página como estafa",
    popup_working: "Un momento...",
    popup_failed: "No funcionó. Inténtelo de nuevo.",
    popup_reported_here: "Usted reportó {host} como estafa, por eso Guardian le avisa aquí.",
    popup_report_undo: "Después de todo, no es una estafa",
    popup_undo_done: "Gracias. Guardian dejará de avisarle sobre {host}.",
    popup_report_correct: "Me equivoqué, esto SÍ es una estafa",
    popup_report_none: "Ahora mismo no hay ningún sitio web abierto para reportar.",
    popup_report_done: "Gracias. Guardian le avisará sobre {host} de ahora en adelante.",
    popup_report_google: "Repórtelo también a Google (esto envía la dirección web a Google)",
    popup_adshield_label: "Bloquear los botones «Descargar» falsos en sitios de descargas",
    popup_quiet_here: "Usted le dijo a Guardian que {host} está bien, así que no le avisa aquí.",
    popup_quiet_undo: "Volver a avisarme en este sitio",
    popup_quiet_undone: "Listo. Guardian volverá a revisar {host} normalmente.",
    popup_adshield_note: "Usted lo ha corregido {n} veces.",
    popup_adshield_note_one: "Usted lo ha corregido una vez.",

    // "¿Esto es una estafa?" encontró un ENLACE peligroso en una página que
    // por lo demás parece normal.
    answer_quiet_main: "Usted le dijo a Guardian que este sitio está bien",
    answer_quiet_sub: "Guardian sí encontró algo aquí, pero no avisa porque usted dijo que este sitio está bien. Si cambió de opinión, pulse «Volver a avisarme en este sitio» justo abajo.",
    answer_links_main: "Cuidado: un enlace de esta página no es seguro",
    answer_links_sub: "La página en sí parece normal, pero uno de sus enlaces lleva a {host}, un sitio reportado como estafa. No haga clic en los enlaces de esta página.",
    answer_lookalike_main: "Cuidado: aquí hay un enlace que finge ser {target}",
    answer_lookalike_sub: "La página en sí parece normal, pero uno de sus enlaces lleva a {host}. Esa dirección está escrita para parecerse a {target} y no es el sitio verdadero. No haga clic ni escriba su contraseña allí.",

    // Consejo tranquilo en páginas de descargas con anuncios
    download_tip: "Consejo de Guardian: en sitios de descargas como este, los botones «Descargar» más grandes y llamativos suelen ser anuncios. La descarga verdadera suele ser un enlace más pequeño junto al nombre del programa. Si un archivo empieza a descargarse solo, no lo abra.",

    // Aviso suave (la página PODRÍA ser una estafa, no es seguro)
    caution_text: "Guardian: esta página podría no ser segura. Tenga cuidado y no escriba su contraseña ni datos personales a menos que confíe en ella.",
    caution_dismiss: "Entendido",
    // Se muestra en lugar del aviso de pantalla completa cuando la persona ya
    // ha dicho que este sitio está bien.
    caution_dismissed: "Usted le dijo a Guardian que este sitio está bien, así que esto es solo un recordatorio. Tenga cuidado aquí: no escriba su contraseña, el número de su tarjeta ni datos personales a menos que esté seguro.",
    caution_never: "No me lo recuerdes más en este sitio",

    // Aviso en pantalla
    banner_heading_page: "ALTO. Esto es una estafa.",
    banner_heading_email: "Este correo parece una estafa",
    banner_close: "Cerrar esta página",
    banner_dismiss_page: "No es una estafa, mostrar la página",
    banner_dismiss_email: "Descartar este aviso",
    banner_footer: "Protegido por Guardian",
    // Los indicios concretos detrás de un aviso, en una lista breve.
    signal_lookalike: "La dirección está escrita para parecerse a {target}, pero no es la verdadera",
    signal_reported: "Investigadores de seguridad reportaron este sitio como estafa",
    signal_reported_self: "Usted le dijo a Guardian que este sitio es una estafa",
    signal_tld: "La dirección termina en {tld}, una terminación muy usada por estafadores",
    signal_punycode: "La dirección usa letras extranjeras que parecen inglesas",
    signal_hyphens: "La dirección está rellenada con palabras y guiones extra",
    signal_digits: "La dirección tiene números mezclados en el nombre",
    signal_password: "Esta página pide una contraseña",
    signal_insecure: "La conexión no es privada (sin candado)",
    signal_virus: "Dice que su computadora tiene un virus",
    signal_threats: "Lo amenaza con arresto, multas o perder su cuenta",
    signal_credentials: "Quiere su contraseña o sus datos personales",
    signal_delivery: "Finge ser una entrega perdida",
    signal_prizes: "Dice que usted ganó un premio",
    signal_payment: "Pide tarjetas de regalo, transferencias o cripto",
    signal_giftcard: "Le pide comprar tarjetas de regalo y leer los códigos",
    signal_bill: "Parece una factura por algo que usted no compró",
    signal_crypto: "Pide la frase de recuperación de su billetera cripto",
    signal_urgency: "Intenta apurarlo para que actúe rápido",

    // Aviso de programas de control remoto
    remote_heading: "Deténgase y piense.",
    remote_text: "¿Alguien por teléfono le está pidiendo instalar este programa? Cuelgue ahora. Eso es una estafa. Las empresas de verdad nunca llaman para controlar su computadora.",
    remote_dismiss: "Nadie me lo pidió, continuar",

    // Notificaciones
    notif_title_site: "Guardian bloqueó una estafa",
    notif_title_email: "Guardian detectó un correo de estafa",

    // Ventana del botón
    popup_blocked: "estafas bloqueadas",
    popup_week: "esta semana",
    popup_websites: "sitios web",
    popup_emails: "correos",
    popup_button: "¿Es esto|una estafa?",
    popup_checking: "Revisando...",
    popup_hint: "¿No está seguro de la página donde está? Presione el botón.",
    popup_footer: "La revisión ocurre en esta computadora. Guardian descarga listas públicas de sitios de estafa conocidos, pero nunca envía las páginas que usted visita ni sus datos.",
    answer_scam_main: "Esto es una ESTAFA.",
    answer_scam_sub: "Cierre esta página. No escriba nada. No llame a ningún número.",
    answer_ok_main: "Esta página se ve bien.",
    answer_ok_sub: "No encontramos señales de estafa. Aun así, nunca escriba una contraseña después de hacer clic en un enlace que alguien le envió.",
    answer_careful_main: "Tenga cuidado.",
    answer_careful_sub: "Esta página muestra señales de advertencia. Si usted no la esperaba, ciérrela.",
    answer_signin_main: "No inicie sesión aquí.",
    answer_signin_sub: "Esta página pide iniciar sesión con Google. Hágalo solamente en el sitio de Google. Si alguien le envió este enlace, cierre la página.",
    answer_remote_main: "Deténgase y piense.",
    answer_remote_sub: "Este programa deja que otra persona controle su computadora. Si alguien por teléfono le pidió instalarlo, cuelgue: eso es una estafa.",
    answer_cant_main: "No pudimos revisar esta página.",
    answer_cant_sub: "Ciérrela, ábrala de nuevo y presione el botón otra vez."
  },

  // NOTE: the languages below cover the visible warnings a senior sees. Any
  // key not present here falls back to English automatically (see guardianT),
  // so partial coverage degrades gracefully. Machine-assisted translations:
  // have a native speaker review before store submission. The on-device AI
  // tier is language-agnostic and already detects scams in these languages
  // regardless of these strings.

  de: {
    reason_techSupport: "Diese Seite gibt sich als Viruswarnung aus. Echte Firmen zeigen niemals eine Telefonnummer wie diese.",
    reason_credentials: "Diese Seite will Sie drängen, Ihr Passwort oder persönliche Daten einzugeben.",
    reason_giftCardAsk: "Hier sollen Sie Geschenkkarten kaufen und die Codes weitergeben. Das ist immer Betrug, egal wer danach fragt.",
    reason_generic: "Diese Seite sieht nach Betrug aus.",
    reason_reported_site: "Diese Website wurde als Betrug gemeldet. Geben Sie hier nichts ein und rufen Sie keine angezeigte Nummer an.",
    reason_brand: "Diese Seite gibt sich als {brand} aus, ist aber nicht die echte {brand}-Website. Geben Sie hier nichts ein.",
    reason_clone: "Diese Seite gibt sich als {brand}-Anmeldeseite aus. Die echte {brand}-Anmeldung gibt es nur auf {domain}. Geben Sie hier nichts ein.",
    banner_heading_page: "STOPP. Das ist Betrug.",
    banner_heading_email: "Diese E-Mail sieht nach Betrug aus",
    banner_close: "Diese Seite schließen",
    banner_dismiss_page: "Das ist kein Betrug, Seite anzeigen",
    banner_footer: "Geschützt durch Guardian",
    remote_heading: "Halten Sie inne und denken Sie nach.",
    remote_text: "Sagt Ihnen jemand am Telefon, Sie sollen dieses Programm installieren? Legen Sie sofort auf. Das ist Betrug. Echte Firmen rufen Sie nie an, um Ihren Computer zu steuern.",
    remote_dismiss: "Niemand hat mich darum gebeten, fortfahren",
    notif_title_site: "Guardian hat einen Betrug blockiert",
    notif_title_email: "Guardian hat eine Betrugs-E-Mail markiert",
    popup_blocked: "blockierte Betrugsfälle",
    popup_button: "Ist das|Betrug?",
    popup_checking: "Wird geprüft...",
    popup_hint: "Unsicher bei der Seite, auf der Sie sind? Drücken Sie den Knopf.",
    answer_scam_main: "Das ist BETRUG.",
    answer_scam_sub: "Schließen Sie diese Seite. Geben Sie nichts ein. Rufen Sie keine Nummern an.",
    answer_ok_main: "Diese Seite sieht in Ordnung aus."
  },

  fr: {
    reason_techSupport: "Cette page se fait passer pour une alerte antivirus. Les vraies entreprises n'affichent jamais un numéro de téléphone ainsi.",
    reason_credentials: "Cette page essaie de vous presser de taper votre mot de passe ou vos informations personnelles.",
    reason_giftCardAsk: "On vous demande d'acheter des cartes-cadeaux et d'en partager les codes. C'est toujours une arnaque, peu importe qui le demande.",
    reason_generic: "Cette page ressemble à une arnaque.",
    reason_reported_site: "Ce site a été signalé comme une arnaque. N'entrez rien ici et n'appelez aucun numéro affiché.",
    reason_brand: "Cette page se fait passer pour {brand} mais ce n'est pas le vrai site {brand}. N'entrez rien ici.",
    reason_clone: "Cette page imite la page de connexion {brand}. La vraie connexion {brand} n'existe que sur {domain}. N'entrez rien ici.",
    banner_heading_page: "STOP. Ceci est une arnaque.",
    banner_heading_email: "Cet e-mail ressemble à une arnaque",
    banner_close: "Fermer cette page",
    banner_dismiss_page: "Ce n'est pas une arnaque, afficher la page",
    banner_footer: "Protégé par Guardian",
    remote_heading: "Arrêtez-vous et réfléchissez.",
    remote_text: "Quelqu'un au téléphone vous dit d'installer ce programme ? Raccrochez maintenant. C'est une arnaque. Les vraies entreprises ne vous appellent jamais pour contrôler votre ordinateur.",
    remote_dismiss: "Personne ne me l'a demandé, continuer",
    notif_title_site: "Guardian a bloqué une arnaque",
    notif_title_email: "Guardian a signalé un e-mail frauduleux",
    popup_blocked: "arnaques bloquées",
    popup_button: "Est-ce une|arnaque ?",
    popup_checking: "Vérification...",
    popup_hint: "Pas sûr de la page où vous êtes ? Appuyez sur le bouton.",
    answer_scam_main: "C'est une ARNAQUE.",
    answer_scam_sub: "Fermez cette page. N'entrez rien. N'appelez aucun numéro.",
    answer_ok_main: "Cette page semble correcte."
  },

  it: {
    reason_techSupport: "Questa pagina finge di essere un avviso antivirus. Le aziende vere non mostrano mai un numero di telefono così.",
    reason_credentials: "Questa pagina cerca di farti scrivere in fretta la tua password o i tuoi dati personali.",
    reason_giftCardAsk: "Ti chiedono di comprare carte regalo e condividere i codici. È sempre una truffa, chiunque lo chieda.",
    reason_generic: "Questa pagina sembra una truffa.",
    reason_reported_site: "Questo sito è stato segnalato come truffa. Non inserire nulla qui e non chiamare nessun numero mostrato.",
    reason_brand: "Questa pagina finge di essere {brand} ma non è il vero sito {brand}. Non inserire nulla qui.",
    reason_clone: "Questa pagina imita la pagina di accesso di {brand}. Il vero accesso {brand} avviene solo su {domain}. Non inserire nulla qui.",
    banner_heading_page: "STOP. Questa è una truffa.",
    banner_heading_email: "Questa email sembra una truffa",
    banner_close: "Chiudi questa pagina",
    banner_dismiss_page: "Non è una truffa, mostra la pagina",
    banner_footer: "Protetto da Guardian",
    remote_heading: "Fermati e rifletti.",
    remote_text: "Qualcuno al telefono ti dice di installare questo programma? Riaggancia subito. È una truffa. Le aziende vere non ti chiamano mai per controllare il tuo computer.",
    remote_dismiss: "Nessuno me l'ha chiesto, continua",
    notif_title_site: "Guardian ha bloccato una truffa",
    notif_title_email: "Guardian ha segnalato un'email truffa",
    popup_blocked: "truffe bloccate",
    popup_button: "È una|truffa?",
    popup_checking: "Controllo...",
    popup_hint: "Non sei sicuro della pagina in cui sei? Premi il pulsante.",
    answer_scam_main: "Questa è una TRUFFA.",
    answer_scam_sub: "Chiudi questa pagina. Non inserire nulla. Non chiamare nessun numero.",
    answer_ok_main: "Questa pagina sembra a posto."
  },

  pt: {
    reason_techSupport: "Esta página finge ser um aviso de vírus. Empresas de verdade nunca mostram um número de telefone assim.",
    reason_credentials: "Esta página tenta apressá-lo a digitar sua senha ou dados pessoais.",
    reason_giftCardAsk: "Estão pedindo para você comprar cartões-presente e compartilhar os códigos. Isso é sempre golpe, não importa quem peça.",
    reason_generic: "Esta página parece um golpe.",
    reason_reported_site: "Este site foi denunciado como golpe. Não digite nada aqui e não ligue para nenhum número mostrado.",
    reason_brand: "Esta página finge ser {brand}, mas não é o site verdadeiro da {brand}. Não digite nada aqui.",
    reason_clone: "Esta página imita a página de login da {brand}. O login verdadeiro da {brand} só existe em {domain}. Não digite nada aqui.",
    banner_heading_page: "PARE. Isto é um golpe.",
    banner_heading_email: "Este e-mail parece um golpe",
    banner_close: "Fechar esta página",
    banner_dismiss_page: "Não é golpe, mostrar a página",
    banner_footer: "Protegido pelo Guardian",
    remote_heading: "Pare e pense.",
    remote_text: "Alguém no telefone está mandando você instalar este programa? Desligue agora. Isso é golpe. Empresas de verdade nunca ligam para controlar seu computador.",
    remote_dismiss: "Ninguém me pediu, continuar",
    notif_title_site: "O Guardian bloqueou um golpe",
    notif_title_email: "O Guardian sinalizou um e-mail de golpe",
    popup_blocked: "golpes bloqueados",
    popup_button: "Isto é|golpe?",
    popup_checking: "Verificando...",
    popup_hint: "Não tem certeza sobre a página em que está? Aperte o botão.",
    answer_scam_main: "Isto é um GOLPE.",
    answer_scam_sub: "Feche esta página. Não digite nada. Não ligue para nenhum número.",
    answer_ok_main: "Esta página parece boa."
  },

  nl: {
    reason_techSupport: "Deze pagina doet zich voor als een viruswaarschuwing. Echte bedrijven tonen nooit zo'n telefoonnummer.",
    reason_credentials: "Deze pagina probeert u te haasten om uw wachtwoord of persoonlijke gegevens in te typen.",
    reason_giftCardAsk: "U wordt gevraagd cadeaubonnen te kopen en de codes te delen. Dat is altijd oplichting, wie het ook vraagt.",
    reason_generic: "Deze pagina lijkt oplichting.",
    reason_reported_site: "Deze website is gemeld als oplichting. Vul hier niets in en bel geen enkel getoond nummer.",
    reason_brand: "Deze pagina doet zich voor als {brand} maar is niet de echte {brand}-website. Vul hier niets in.",
    reason_clone: "Deze pagina imiteert de inlogpagina van {brand}. Het echte {brand}-inloggen bestaat alleen op {domain}. Vul hier niets in.",
    banner_heading_page: "STOP. Dit is oplichting.",
    banner_heading_email: "Deze e-mail lijkt oplichting",
    banner_close: "Deze pagina sluiten",
    banner_dismiss_page: "Dit is geen oplichting, toon de pagina",
    banner_footer: "Beschermd door Guardian",
    remote_heading: "Stop en denk na.",
    remote_text: "Zegt iemand aan de telefoon dat u dit programma moet installeren? Hang nu op. Dit is oplichting. Echte bedrijven bellen u nooit om uw computer te bedienen.",
    remote_dismiss: "Niemand heeft mij dit gevraagd, doorgaan",
    notif_title_site: "Guardian heeft oplichting geblokkeerd",
    notif_title_email: "Guardian heeft een oplichtingsmail gemarkeerd",
    popup_blocked: "geblokkeerde oplichting",
    popup_button: "Is dit|oplichting?",
    popup_checking: "Bezig met controleren...",
    popup_hint: "Niet zeker over de pagina waar u bent? Druk op de knop.",
    answer_scam_main: "Dit is OPLICHTING.",
    answer_scam_sub: "Sluit deze pagina. Vul niets in. Bel geen enkel nummer.",
    answer_ok_main: "Deze pagina ziet er goed uit."
  },

  ro: {
    reason_techSupport: "Această pagină se preface că este o avertizare de virus. Firmele adevărate nu afișează niciodată un număr de telefon așa.",
    reason_credentials: "Această pagină încearcă să vă grăbească să tastați parola sau datele personale.",
    reason_giftCardAsk: "Vi se cere să cumpărați carduri cadou și să dați codurile. Este mereu o înșelătorie, indiferent cine cere.",
    reason_generic: "Această pagină pare o înșelătorie.",
    reason_reported_site: "Acest site a fost raportat ca înșelătorie. Nu introduceți nimic aici și nu sunați la niciun număr afișat.",
    reason_brand: "Această pagină se preface că este {brand}, dar nu este site-ul adevărat {brand}. Nu introduceți nimic aici.",
    reason_clone: "Această pagină imită pagina de conectare {brand}. Conectarea adevărată {brand} există doar pe {domain}. Nu introduceți nimic aici.",
    banner_heading_page: "STOP. Aceasta este o înșelătorie.",
    banner_heading_email: "Acest e-mail pare o înșelătorie",
    banner_close: "Închide această pagină",
    banner_dismiss_page: "Nu este înșelătorie, arată pagina",
    banner_footer: "Protejat de Guardian",
    remote_heading: "Opriți-vă și gândiți-vă.",
    remote_text: "Vă spune cineva la telefon să instalați acest program? Închideți telefonul acum. Este o înșelătorie. Firmele adevărate nu vă sună niciodată ca să vă controleze calculatorul.",
    remote_dismiss: "Nimeni nu mi-a cerut asta, continuă",
    notif_title_site: "Guardian a blocat o înșelătorie",
    notif_title_email: "Guardian a semnalat un e-mail de înșelătorie",
    popup_blocked: "înșelătorii blocate",
    popup_button: "Este o|înșelătorie?",
    popup_checking: "Se verifică...",
    popup_hint: "Nu sunteți sigur de pagina pe care sunteți? Apăsați butonul.",
    answer_scam_main: "Aceasta este o ÎNȘELĂTORIE.",
    answer_scam_sub: "Închideți această pagină. Nu introduceți nimic. Nu sunați la niciun număr.",
    answer_ok_main: "Această pagină pare în regulă."
  },

  pl: {
    reason_techSupport: "Ta strona udaje ostrzeżenie o wirusie. Prawdziwe firmy nigdy nie pokazują takiego numeru telefonu.",
    reason_credentials: "Ta strona próbuje pospieszyć Cię do wpisania hasła lub danych osobowych.",
    reason_reported_site: "Ta strona została zgłoszona jako oszustwo. Nie wpisuj tu niczego i nie dzwoń pod żaden numer.",
    reason_generic: "Ta strona wygląda na oszustwo.",
    banner_heading_page: "STOP. To jest oszustwo.",
    banner_close: "Zamknij tę stronę",
    banner_dismiss_page: "To nie oszustwo, pokaż stronę",
    banner_footer: "Chronione przez Guardian",
    remote_heading: "Zatrzymaj się i pomyśl.",
    remote_text: "Czy ktoś przez telefon każe Ci zainstalować ten program? Rozłącz się teraz. To oszustwo. Prawdziwe firmy nigdy nie dzwonią, by przejąć Twój komputer.",
    popup_button: "Czy to|oszustwo?",
    popup_blocked: "zablokowane oszustwa",
    answer_scam_main: "To jest OSZUSTWO.",
    answer_scam_sub: "Zamknij tę stronę. Nie wpisuj niczego. Nie dzwoń pod żaden numer.",
    answer_ok_main: "Ta strona wygląda w porządku."
  },

  ru: {
    reason_techSupport: "Эта страница притворяется предупреждением о вирусе. Настоящие компании никогда не показывают такой номер телефона.",
    reason_credentials: "Эта страница пытается заставить вас поскорее ввести пароль или личные данные.",
    reason_reported_site: "Этот сайт помечен как мошеннический. Ничего здесь не вводите и не звоните по указанным номерам.",
    reason_generic: "Эта страница похожа на мошенничество.",
    banner_heading_page: "СТОП. Это мошенничество.",
    banner_close: "Закрыть эту страницу",
    banner_dismiss_page: "Это не мошенничество, показать страницу",
    banner_footer: "Защищено Guardian",
    remote_heading: "Остановитесь и подумайте.",
    remote_text: "Кто-то по телефону просит установить эту программу? Положите трубку. Это мошенничество. Настоящие компании никогда не звонят, чтобы управлять вашим компьютером.",
    popup_button: "Это|мошенничество?",
    popup_blocked: "заблокировано мошенничеств",
    answer_scam_main: "Это МОШЕННИЧЕСТВО.",
    answer_scam_sub: "Закройте эту страницу. Ничего не вводите. Не звоните по номерам.",
    answer_ok_main: "Эта страница выглядит нормально."
  },

  ar: {
    reason_techSupport: "هذه الصفحة تتظاهر بأنها تحذير من فيروس. الشركات الحقيقية لا تعرض رقم هاتف بهذه الطريقة أبداً.",
    reason_credentials: "هذه الصفحة تحاول استعجالك لكتابة كلمة مرورك أو معلوماتك الشخصية.",
    reason_reported_site: "تم الإبلاغ عن هذا الموقع كموقع احتيالي. لا تكتب أي شيء هنا ولا تتصل بأي رقم معروض.",
    reason_generic: "تبدو هذه الصفحة احتيالاً.",
    banner_heading_page: "توقف. هذا احتيال.",
    banner_close: "أغلق هذه الصفحة",
    banner_dismiss_page: "هذا ليس احتيالاً، أظهر الصفحة",
    banner_footer: "محمي بواسطة Guardian",
    remote_heading: "توقف وفكر.",
    remote_text: "هل يطلب منك شخص عبر الهاتف تثبيت هذا البرنامج؟ أغلق الهاتف الآن. هذا احتيال. الشركات الحقيقية لا تتصل بك أبداً للتحكم في حاسوبك.",
    popup_button: "هل هذا|احتيال؟",
    popup_blocked: "عمليات احتيال محظورة",
    answer_scam_main: "هذا احتيال.",
    answer_scam_sub: "أغلق هذه الصفحة. لا تكتب أي شيء. لا تتصل بأي رقم.",
    answer_ok_main: "تبدو هذه الصفحة سليمة."
  },

  zh: {
    reason_techSupport: "此页面假装是病毒警告。真正的公司绝不会这样显示电话号码。",
    reason_credentials: "此页面试图催促您输入密码或个人信息。",
    reason_reported_site: "此网站已被举报为诈骗。请勿在此输入任何内容，也不要拨打页面上的任何电话。",
    reason_generic: "此页面看起来像诈骗。",
    banner_heading_page: "停。这是诈骗。",
    banner_close: "关闭此页面",
    banner_dismiss_page: "这不是诈骗，显示页面",
    banner_footer: "由 Guardian 保护",
    remote_heading: "停下来想一想。",
    remote_text: "有人在电话里让您安装这个程序吗？请立即挂断。这是诈骗。真正的公司绝不会打电话来控制您的电脑。",
    popup_button: "这是|诈骗吗？",
    popup_blocked: "已拦截的诈骗",
    answer_scam_main: "这是诈骗。",
    answer_scam_sub: "关闭此页面。不要输入任何内容。不要拨打任何号码。",
    answer_ok_main: "此页面看起来没问题。"
  },

  ja: {
    reason_techSupport: "このページはウイルス警告のふりをしています。本物の会社がこのように電話番号を表示することは決してありません。",
    reason_credentials: "このページはあなたを急かしてパスワードや個人情報を入力させようとしています。",
    reason_reported_site: "このサイトは詐欺として報告されています。ここには何も入力せず、表示された電話番号にかけないでください。",
    reason_generic: "このページは詐欺のようです。",
    banner_heading_page: "ストップ。これは詐欺です。",
    banner_close: "このページを閉じる",
    banner_dismiss_page: "詐欺ではありません、ページを表示",
    banner_footer: "Guardian が保護しています",
    remote_heading: "立ち止まって考えてください。",
    remote_text: "電話で誰かがこのプログラムをインストールするよう言っていますか？今すぐ電話を切ってください。これは詐欺です。本物の会社があなたのパソコンを操作するために電話することはありません。",
    popup_button: "これは|詐欺？",
    popup_blocked: "ブロックした詐欺",
    answer_scam_main: "これは詐欺です。",
    answer_scam_sub: "このページを閉じてください。何も入力しないでください。どの番号にもかけないでください。",
    answer_ok_main: "このページは問題なさそうです。"
  },

  el: {
    reason_techSupport: "Αυτή η σελίδα προσποιείται ότι είναι προειδοποίηση ιού. Οι πραγματικές εταιρείες δεν δείχνουν ποτέ έναν αριθμό τηλεφώνου έτσι.",
    reason_credentials: "Αυτή η σελίδα προσπαθεί να σας βιάσει να πληκτρολογήσετε τον κωδικό ή τα προσωπικά σας στοιχεία.",
    reason_reported_site: "Αυτός ο ιστότοπος έχει αναφερθεί ως απάτη. Μην πληκτρολογήσετε τίποτα εδώ και μην καλέσετε κανέναν αριθμό.",
    reason_generic: "Αυτή η σελίδα μοιάζει με απάτη.",
    banner_heading_page: "ΣΤΟΠ. Αυτή είναι απάτη.",
    banner_close: "Κλείστε αυτή τη σελίδα",
    banner_dismiss_page: "Δεν είναι απάτη, δείξε τη σελίδα",
    banner_footer: "Προστασία από το Guardian",
    remote_heading: "Σταματήστε και σκεφτείτε.",
    remote_text: "Σας λέει κάποιος στο τηλέφωνο να εγκαταστήσετε αυτό το πρόγραμμα; Κλείστε το τηλέφωνο τώρα. Είναι απάτη. Οι πραγματικές εταιρείες δεν σας καλούν ποτέ για να ελέγξουν τον υπολογιστή σας.",
    popup_button: "Είναι|απάτη;",
    popup_blocked: "μπλοκαρισμένες απάτες",
    answer_scam_main: "Αυτή είναι ΑΠΑΤΗ.",
    answer_scam_sub: "Κλείστε αυτή τη σελίδα. Μην πληκτρολογήσετε τίποτα. Μην καλέσετε κανέναν αριθμό.",
    answer_ok_main: "Αυτή η σελίδα φαίνεται εντάξει."
  },

  hu: {
    reason_techSupport: "Ez az oldal vírusfigyelmeztetésnek adja ki magát. Az igazi cégek soha nem mutatnak így telefonszámot.",
    reason_credentials: "Ez az oldal siettetni próbálja, hogy beírja a jelszavát vagy személyes adatait.",
    reason_reported_site: "Ezt az oldalt átverésként jelentették. Ne írjon be ide semmit, és ne hívjon fel semmilyen megjelenített számot.",
    reason_generic: "Ez az oldal átverésnek tűnik.",
    banner_heading_page: "ÁLLJ. Ez átverés.",
    banner_close: "Oldal bezárása",
    banner_dismiss_page: "Ez nem átverés, mutasd az oldalt",
    banner_footer: "A Guardian védi",
    remote_heading: "Álljon meg és gondolkodjon.",
    remote_text: "Valaki telefonon azt mondja, telepítse ezt a programot? Tegye le most a telefont. Ez átverés. Az igazi cégek soha nem hívják fel, hogy irányítsák a számítógépét.",
    popup_button: "Ez|átverés?",
    popup_blocked: "blokkolt átverések",
    answer_scam_main: "Ez ÁTVERÉS.",
    answer_scam_sub: "Zárja be ezt az oldalt. Ne írjon be semmit. Ne hívjon fel semmilyen számot.",
    answer_ok_main: "Ez az oldal rendben lévőnek tűnik."
  },

  sv: {
    reason_techSupport: "Den här sidan låtsas vara en virusvarning. Riktiga företag visar aldrig ett telefonnummer så här.",
    reason_credentials: "Den här sidan försöker stressa dig att skriva ditt lösenord eller personliga uppgifter.",
    reason_reported_site: "Den här webbplatsen har rapporterats som en bluff. Skriv inget här och ring inget nummer som visas.",
    reason_generic: "Den här sidan verkar vara en bluff.",
    banner_heading_page: "STOPP. Det här är en bluff.",
    banner_close: "Stäng den här sidan",
    banner_dismiss_page: "Det är ingen bluff, visa sidan",
    banner_footer: "Skyddad av Guardian",
    remote_heading: "Stanna upp och tänk efter.",
    remote_text: "Säger någon i telefon att du ska installera det här programmet? Lägg på nu. Det är en bluff. Riktiga företag ringer aldrig för att styra din dator.",
    popup_button: "Är det här|en bluff?",
    popup_blocked: "blockerade bluffar",
    answer_scam_main: "Det här är en BLUFF.",
    answer_scam_sub: "Stäng den här sidan. Skriv inget. Ring inget nummer.",
    answer_ok_main: "Den här sidan ser okej ut."
  },

  da: {
    reason_techSupport: "Denne side foregiver at være en virusadvarsel. Rigtige firmaer viser aldrig et telefonnummer på denne måde.",
    reason_credentials: "Denne side prøver at stresse dig til at skrive din adgangskode eller personlige oplysninger.",
    reason_reported_site: "Denne hjemmeside er blevet anmeldt som svindel. Skriv ikke noget her, og ring ikke til noget vist nummer.",
    reason_generic: "Denne side ligner svindel.",
    banner_heading_page: "STOP. Dette er svindel.",
    banner_close: "Luk denne side",
    banner_dismiss_page: "Det er ikke svindel, vis siden",
    banner_footer: "Beskyttet af Guardian",
    remote_heading: "Stop op og tænk.",
    remote_text: "Siger nogen i telefonen, at du skal installere dette program? Læg på nu. Det er svindel. Rigtige firmaer ringer aldrig for at styre din computer.",
    popup_button: "Er dette|svindel?",
    popup_blocked: "blokerede svindelnumre",
    answer_scam_main: "Dette er SVINDEL.",
    answer_scam_sub: "Luk denne side. Skriv ikke noget. Ring ikke til noget nummer.",
    answer_ok_main: "Denne side ser fin ud."
  },

  no: {
    reason_techSupport: "Denne siden later som den er en virusadvarsel. Ekte selskaper viser aldri et telefonnummer på denne måten.",
    reason_credentials: "Denne siden prøver å stresse deg til å skrive passordet eller de personlige opplysningene dine.",
    reason_reported_site: "Dette nettstedet er meldt som svindel. Ikke skriv noe her, og ikke ring noe nummer som vises.",
    reason_generic: "Denne siden ser ut som svindel.",
    banner_heading_page: "STOPP. Dette er svindel.",
    banner_close: "Lukk denne siden",
    banner_dismiss_page: "Det er ikke svindel, vis siden",
    banner_footer: "Beskyttet av Guardian",
    remote_heading: "Stopp og tenk deg om.",
    remote_text: "Sier noen på telefonen at du skal installere dette programmet? Legg på nå. Dette er svindel. Ekte selskaper ringer aldri for å styre datamaskinen din.",
    popup_button: "Er dette|svindel?",
    popup_blocked: "blokkerte svindelforsøk",
    answer_scam_main: "Dette er SVINDEL.",
    answer_scam_sub: "Lukk denne siden. Ikke skriv noe. Ikke ring noe nummer.",
    answer_ok_main: "Denne siden ser grei ut."
  }
};

// The 18 supported interface languages, by ISO code.
const GUARDIAN_SUPPORTED_LANGS = [
  "en", "es", "de", "fr", "it", "pt", "nl", "ro", "pl", "ru", "ar", "zh",
  "ja", "el", "hu", "sv", "da", "no"
];

// Which of the 18 interface languages to use, from the browser's language.
function guardianLang() {
  if (typeof navigator === "undefined") return "en";
  const raw = (navigator.language || "en").toLowerCase();
  const two = raw.slice(0, 2);
  if (two === "nb" || two === "nn") return "no"; // Norwegian variants
  if (two === "zh") return "zh";
  return GUARDIAN_STRINGS[two] ? two : "en";
}

// Look up a string in the current language, falling back to English per key
// so partial translations degrade gracefully. {vars} are interpolated.
function guardianT(key, vars) {
  const lang = guardianLang();
  let s =
    (GUARDIAN_STRINGS[lang] && GUARDIAN_STRINGS[lang][key]) ||
    GUARDIAN_STRINGS.en[key] ||
    key;
  if (vars) {
    for (const k of Object.keys(vars)) {
      s = s.split("{" + k + "}").join(vars[k]);
    }
  }
  return s;
}
