"""
Online checks for the scam checker: things that text alone can't show.

Network functions return:
  - None              if they could not run (no internet, no data)
  - (points, reasons) if they ran
so the main checker can tell "checked and fine" from "could not check".

The page-source checks (analyze_html, analyze_scripts, analyze_links) never
use the internet. They only read the HTML you give them.
"""

import ipaddress
import os
import re
import socket
import ssl
import unicodedata
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

TIMEOUT = 8
HEADERS = {"User-Agent": "Mozilla/5.0"}

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd", "rb.gy"]
RISKY_ENDINGS = [".xyz", ".top", ".click", ".work", ".tk", ".gq", ".ml"]

# Endings with two parts, so "gtbank.com.ng" is treated as one domain
TWO_PART_ENDINGS = {
    "com.ng", "org.ng", "gov.ng", "edu.ng", "com.dz", "gov.dz", "org.dz",
    "co.uk", "co.za", "com.au", "com.br",
}
SENSITIVE_FIELDS = {"pin", "cvv", "cvc", "otp", "bvn"}


# ---------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------
def get_host(url):
    has_scheme = url.lower().startswith(("http://", "https://"))
    parsed = urlparse(url if has_scheme else "//" + url)
    return (parsed.hostname or "").lower()


def registered_domain(host):
    """login.secure.paypal.com -> paypal.com"""
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_ENDINGS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_suspicious_host(host):
    return (
        bool(re.fullmatch(r"[\d.]+", host))
        or any(host.endswith(e) for e in RISKY_ENDINGS)
        or any(host == s or host.endswith("." + s) for s in SHORTENERS)
    )


# ---------------------------------------------------------------
# CHECK 1: How old is the domain? Scam sites are usually brand new.
# Uses RDAP, a free public registration database (no key needed).
# ---------------------------------------------------------------
def domain_age_days(rdap_data, now=None):
    for event in rdap_data.get("events", []):
        if event.get("eventAction") == "registration":
            try:
                date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                return None
            return ((now or datetime.now(timezone.utc)) - date).days
    return None


def lookup_domain_age(host):
    domain = registered_domain(host)
    if not domain:
        return None
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}",
                                timeout=TIMEOUT, headers=HEADERS)
        if not response.ok:
            return None  # some country domains (.dz, .ng) may not be in RDAP
        days = domain_age_days(response.json())
    except (requests.RequestException, ValueError):
        return None
    if days is None:
        return None
    if days < 30:
        return 5, [f"Website domain was registered only {days} days ago (+5)"]
    if days < 180:
        return 3, [f"Website domain is only {days} days old (+3)"]
    return 0, []


# ---------------------------------------------------------------
# CHECK 2: Is the website's security certificate valid?
# (expired, self-signed, or issued for a different website)
# ---------------------------------------------------------------
def check_certificate(host):
    if not host or not is_public_host(host):
        return None
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return 0, []
    except ssl.SSLCertVerificationError as error:
        return 4, [f"Website security certificate is not valid: {error.verify_message} (+4)"]
    except (OSError, ssl.SSLError):
        return None


# ---------------------------------------------------------------
# CHECK 3: Google Safe Browsing, a list of known dangerous sites.
# Needs a free API key in the environment variable SAFE_BROWSING_API_KEY.
# Without a key this check is skipped.
# ---------------------------------------------------------------
def safe_browsing(url):
    key = os.environ.get("SAFE_BROWSING_API_KEY")
    if not key:
        return None
    body = {
        "client": {"clientId": "scam-checker", "clientVersion": "1.7"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": key}, json=body, timeout=TIMEOUT,
        )
        if not response.ok:
            return None
        if response.json().get("matches"):
            return 10, ["Google Safe Browsing lists this link as dangerous (+10)"]
    except (requests.RequestException, ValueError):
        return None
    return 0, []


# ---------------------------------------------------------------
# CHECK 4: Where does the link really go?
# ---------------------------------------------------------------
MAX_BYTES = 500_000
MAX_REDIRECTS = 5


def is_public_host(host):
    """False for localhost, home/office networks and other internal addresses.
    A website that opens links for visitors must never open those."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if not address.is_global:
            return False
    return True


def fetch_page(url):
    """Download a page safely: public addresses only, ports 80/443 only,
    redirects followed by hand (each one checked), size capped."""
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    history = []
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(url)
        try:
            port = parsed.port
        except ValueError:
            port = -1
        if port not in (None, 80, 443):
            raise requests.exceptions.InvalidURL("Blocked: unusual port")
        if not is_public_host((parsed.hostname or "").lower()):
            raise requests.exceptions.InvalidURL("Blocked: not a public website address")

        response = requests.get(url, timeout=TIMEOUT, headers=HEADERS,
                                allow_redirects=False, stream=True)
        try:
            location = response.headers.get("Location")
            if response.is_redirect and location:
                history.append(SimpleNamespace(url=url))
                url = urljoin(url, location)
                continue
            body = response.raw.read(MAX_BYTES, decode_content=True)
            content_type = response.headers.get("content-type", "").lower()
            encoding = response.encoding if "charset" in content_type else "utf-8"
            return SimpleNamespace(url=url, text=body.decode(encoding or "utf-8", errors="replace"),
                                   history=history)
        finally:
            response.close()
    raise requests.exceptions.TooManyRedirects("Too many redirects")


def analyze_redirects(chain):
    """chain = list of URLs the link passed through, first to last."""
    points, reasons = 0, []
    if len(chain) - 1 >= 3:
        points += 2
        reasons.append(f"Link bounces through {len(chain) - 1} redirects (+2)")
    first = registered_domain(get_host(chain[0]))
    last = registered_domain(get_host(chain[-1]))
    if first and last and first != last:
        points += 2
        reasons.append(f"Link sends you to a different website: {last} (+2)")
    return points, reasons


# ---------------------------------------------------------------
# CHECK 5: Forms on the page (what happens to what you type?)
# ---------------------------------------------------------------
def analyze_html(html, host=""):
    soup = BeautifulSoup(html, "html.parser")
    points, reasons = 0, []
    own = registered_domain(host)
    insecure_done = foreign_done = False

    for form in soup.find_all("form"):
        if not form.find("input", {"type": "password"}):
            continue
        action = (form.get("action") or "").strip()
        if not insecure_done and action.lower().startswith("http://"):
            points += 3
            reasons.append("Login form sends your password without protection (http) (+3)")
            insecure_done = True
        if not foreign_done and action.startswith(("http://", "https://", "//")):
            target = registered_domain(get_host(action))
            if target and own and target != own:
                points += 5
                reasons.append(
                    f"Login form sends your password to a different website: {target} (+5)"
                )
                foreign_done = True

    # asks for PIN / OTP / CVV / BVN
    found = set()
    for field in soup.find_all("input"):
        text = " ".join(
            str(field.get(a, "")) for a in ("name", "id", "placeholder", "aria-label")
        ).lower()
        found |= set(re.split(r"[^a-z]+", text)) & SENSITIVE_FIELDS
    if found:
        points += 3
        reasons.append(f"Page asks for sensitive details ({', '.join(sorted(found))}) (+3)")

    # invisible iframes are used to load hidden content
    for frame in soup.find_all("iframe"):
        style = (frame.get("style") or "").replace(" ", "").lower()
        if ("display:none" in style or "visibility:hidden" in style
                or frame.get("width") in ("0", "1") or frame.get("height") in ("0", "1")):
            points += 2
            reasons.append("Page contains a hidden frame (+2)")
            break

    return points, reasons


# ---------------------------------------------------------------
# CHECK 6: The page's JavaScript (hidden tricks in the source code)
# Each row: pattern to look for, points, what it means.
# Weak signs get 1-2 points, strong signs get 4-6.
# ---------------------------------------------------------------
SCRIPT_SIGNS = [
    (r"coinhive|coin-hive|cryptonight|crypto-loot|webminer|jsecoin", 6,
     "Page contains code that looks like a crypto miner (uses your device to mine coins)"),
    (r"eval\s*\(\s*(?:atob|unescape|string\.fromcharcode)"
     r"|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k"
     r"|document\.write\s*\(\s*unescape", 4,
     "Page hides its code with obfuscation tricks"),
    (r"notification\.requestpermission", 2,
     "Page asks permission to send you notifications"),
    (r"beforeunload", 2,
     "Page tries to stop you from leaving"),
    (r"contextmenu[^;]{0,80}(?:preventdefault|return\s*false)"
     r"|oncontextmenu\s*=\s*['\"]?\s*return\s+false", 1,
     "Page blocks right-click (often used to hide its code)"),
]


def analyze_scripts(html, host=""):
    soup = BeautifulSoup(html, "html.parser")
    points, reasons = 0, []
    own = registered_domain(host)

    # all inline JavaScript, plus inline handlers like onclick="..."
    parts = [s.get_text() for s in soup.find_all("script") if not s.get("src")]
    for tag in soup.find_all(True):
        parts += [f"{k}={v}" for k, v in tag.attrs.items() if k.startswith("on")]
    code = "\n".join(parts).lower()

    for pattern, pts, message in SCRIPT_SIGNS:
        if re.search(pattern, code):
            points += pts
            reasons.append(f"{message} (+{pts})")

    if (re.search(r"addeventlistener\(\s*['\"]key(?:down|press|up)", code)
            and re.search(r"fetch\(|xmlhttprequest|sendbeacon", code)):
        points += 2
        reasons.append("Page may record what you type and send it somewhere (+2)")

    # code loaded from a suspicious address
    for script in soup.find_all("script", src=True):
        src = script["src"].strip()
        if src.startswith("//"):
            src = "https:" + src
        script_host = get_host(src)
        if (script_host and registered_domain(script_host) != own
                and is_suspicious_host(script_host)):
            points += 3
            reasons.append(f"Page loads code from a suspicious address: {script_host} (+3)")
            break

    return points, reasons


# ---------------------------------------------------------------
# CHECK 7: Links on the page (do they go where they say?)
# ---------------------------------------------------------------
TEXT_IS_URL = re.compile(
    r"^(?:https?://|www\.)\S+$"
    r"|^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|biz|io|co|ng|dz|fr|uk|us|xyz"
    r"|top|app|site|online|shop|gov|edu|de|es)(?:/\S*)?$",
    re.IGNORECASE,
)
PROGRAM_FILE = re.compile(r"\.(?:apk|exe|msi|scr|bat|jar|dmg)(?:$|[?#])")


def analyze_links(html, host=""):
    soup = BeautifulSoup(html, "html.parser")
    points, reasons = 0, []
    own = registered_domain(host)
    mismatch_done = download_done = False

    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if href.startswith("//"):
            href = "https:" + href

        if not download_done and PROGRAM_FILE.search(href.lower()):
            points += 4
            reasons.append("Page offers a program file to download (.apk, .exe ...) (+4)")
            download_done = True

        # the text says paypal.com but the link goes somewhere else
        if not mismatch_done and href.lower().startswith(("http://", "https://")):
            shown_text = link.get_text(strip=True)
            if TEXT_IS_URL.match(shown_text):
                shown = registered_domain(get_host(shown_text))
                real = registered_domain(get_host(href))
                if shown and real and shown != real:
                    points += 5
                    reasons.append(f"A link shows {shown} but really goes to {real} (+5)")
                    mismatch_done = True

    # the page sends you somewhere else automatically
    meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.IGNORECASE)})
    if meta:
        found = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", meta.get("content", ""), re.IGNORECASE)
        if found:
            target = registered_domain(get_host(found.group(1)))
            if target and target != own:
                points += 3
                reasons.append(f"Page automatically sends you to another website: {target} (+3)")

    return points, reasons


# ---------------------------------------------------------------
# CHECKS 8-10: Fake-shop signs, from consumer-fraud checklists.
#   8. Payment: how does the page want to be paid?
#   9. Trust pages: About, Contact, Privacy, Terms, Returns
#  10. Offers: too-good-to-be-true prices, fake urgency, shouting style
# Patterns work on text with accents removed, so "À propos" = "a propos".
# ---------------------------------------------------------------
def _plain(text):
    """lowercase and remove accents / Arabic marks"""
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(ch for ch in text if not unicodedata.combining(ch))


def _rx(pattern):
    return re.compile(_plain(pattern))


def _visible_text(soup):
    """the text a visitor can read (no JavaScript or CSS)"""
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(separator=" ")


SHOP_WORDS = _rx(
    r"add to (?:cart|basket|bag)|buy now|checkout|shopping cart|ajouter au panier|panier"
    r"|acheter|comprar|carrito|اضف الى السلة|اشتر الان|السلة"
)
PRICE = re.compile(
    r"[$€£₦]\s?\d[\d,.]*|\d[\d,.]*\s?(?:[$€£₦]|usd\b|eur\b|ngn\b|dzd\b|da\b)", re.IGNORECASE
)
CARD_FIELD = _rx(r"card.?number|cc.?num|cvv|cvc|numero de carte|numero de tarjeta")

SCAM_PAY = _rx(
    r"(?:pay|payment|paiement|payez|pago|pague|دفع)[^.]{0,40}"
    r"(?:gift ?cards?|western union|moneygram|carte cadeau|tarjeta de regalo)"
)
RISKY_PAY = _rx(
    r"bank transfer|wire transfer|virement|transferencia bancaria|bitcoin|\busdt\b|crypto|zelle|cash ?app"
)
SAFER_PAY = _rx(
    r"visa|mastercard|paypal|stripe|paystack|flutterwave|apple pay|google pay|credit card"
    r"|debit card|carte bancaire|tarjeta de credito|verve|edahabia|\bcib\b|cash on delivery"
    r"|paiement a la livraison|pago contra reembolso|الدفع عند الاستلام"
)

TRUST_LINKS = {
    "about": ["about", "a propos", "qui sommes", "notre histoire", "sobre nosotros",
              "quienes somos", "من نحن"],
    "contact": ["contact", "contacto", "اتصل", "تواصل"],
    "privacy": ["privacy", "confidentialite", "privacidad", "الخصوصية"],
    "terms": ["terms", "conditions", "cgv", "cgu", "terminos", "الشروط", "الاحكام"],
    "returns": ["return", "refund", "retour", "rembours", "devolucion", "reembolso",
                "الارجاع", "الاسترجاع", "استرداد"],
}
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")

DISCOUNT = _rx(
    r"(\d{2,3})\s*%\s*(?:off|discount|de reduction|de remise|de descuento|descuento|reduction|remise)"
    r"|(?:save|economisez|ahorre|up to|jusqu'a|hasta)\s*(\d{2,3})\s*%"
    r"|(?<![\w])-\s?(\d{2,3})\s?%"
)
RETURN_CLAIMS = _rx(
    r"\d{1,4}\s*%\s*(?:per|a|each|every|/|par|al|por)\s*(?:day|daily|week|weekly|hour|jour|semaine|dia|semana)"
    r"|(?:daily|weekly|guaranteed|garanti\w*|garantizad\w*)\s+(?:profits?|returns?|income|gains?|ganancias?|rendement\w*)"
    r"|(?:double|triple|doublez|duplique)\s+(?:your|votre|su)\s+(?:money|argent|dinero|investment)"
)
URGENCY = _rx(
    r"only\s+\d+\s+(?:left|remaining|in stock)|sale ends in|offer (?:ends|expires)|deal expires"
    r"|hurry|dernieres? pieces|il n'en reste que|plus que \d+|solo quedan|ultimas unidades"
)


def _card_fields(soup):
    found = []
    for field in soup.find_all("input"):
        attrs = " ".join(
            str(field.get(a, "")) for a in ("name", "id", "placeholder", "autocomplete", "aria-label")
        )
        if CARD_FIELD.search(_plain(attrs)):
            found.append(field)
    return found


def _is_shop(text, soup):
    return bool(SHOP_WORDS.search(text)) or len(PRICE.findall(text)) >= 3 or bool(_card_fields(soup))


def analyze_payment(html, host="", https=None):
    """https: True / False if known, None if unknown (e.g. saved page)."""
    soup = BeautifulSoup(html, "html.parser")
    cards = _card_fields(soup)
    text = _plain(_visible_text(soup))
    shop = _is_shop(text, soup) or bool(cards)
    points, reasons = 0, []

    if SCAM_PAY.search(text):
        points += 4
        reasons.append("Page asks you to pay with gift cards or money-transfer services (+4)")
    elif shop and RISKY_PAY.search(text) and not SAFER_PAY.search(text):
        points += 4
        reasons.append(
            "Page only offers bank transfer or crypto, with no card or trusted payment provider (+4)"
        )

    if https is False and cards:
        points += 5
        reasons.append("Page asks for card details but does not use https (no padlock) (+5)")
    elif https is False and shop:
        points += 3
        reasons.append("Shop page does not use https (no padlock), so your data is not encrypted (+3)")

    return points, reasons


def analyze_trust(html, host=""):
    """Does a shop show who is behind it? Returns None if the page has too
    few links to judge (it may be built by JavaScript)."""
    soup = BeautifulSoup(html, "html.parser")
    links = soup.find_all("a", href=True)
    if len(links) < 3:
        return None
    text = _plain(_visible_text(soup))
    if not _is_shop(text, soup):
        return 0, []

    labels = " ".join(_plain(a.get_text(" ")) + " " + _plain(a["href"]) for a in links)
    has = {name: any(_plain(w) in labels for w in words) for name, words in TRUST_LINKS.items()}
    points, reasons = 0, []

    if not has["about"] and not has["contact"]:
        points += 3
        reasons.append("Online shop with no About or Contact page: almost no company information (+3)")
    if not has["privacy"] and not has["terms"]:
        points += 2
        reasons.append("Online shop with no privacy policy or terms and conditions (+2)")
    if not has["returns"]:
        points += 2
        reasons.append("Online shop with no returns or refund policy (+2)")

    phone = any(sum(c.isdigit() for c in m) >= 9 for m in PHONE.findall(text))
    mail_link = soup.find("a", href=re.compile(r"^(?:mailto|tel):", re.IGNORECASE))
    if not (phone or EMAIL.search(text) or mail_link):
        points += 2
        reasons.append("No email address or phone number shown anywhere (+2)")

    return points, reasons


def analyze_offers(html, host=""):
    soup = BeautifulSoup(html, "html.parser")
    raw = _visible_text(soup)
    text = _plain(raw)
    shop = _is_shop(text, soup)
    points, reasons = 0, []

    if shop:
        best = 0
        for m in DISCOUNT.finditer(text):
            best = max(best, int(next(g for g in m.groups() if g)))
        if best >= 70:
            points += 3
            reasons.append(f"Prices advertised with {best}% discounts: too good to be true (+3)")

    if RETURN_CLAIMS.search(text):
        points += 5
        reasons.append("Page promises very high or guaranteed returns on money (+5)")

    timer = soup.find(class_=re.compile(r"countdown|timer", re.IGNORECASE))
    if URGENCY.search(text) or timer:
        points += 2
        reasons.append("Page uses fake urgency (countdowns, 'only 3 left', 'hurry') (+2)")

    words = re.findall(r"[A-Za-z]{4,}", raw)
    shouting = len(words) >= 20 and sum(w.isupper() for w in words) / len(words) > 0.3
    if shouting or len(re.findall(r"!{2,}", raw)) >= 3:
        points += 1
        reasons.append("Page is written in a shouting style (CAPITALS, !!!) (+1)")

    return points, reasons
