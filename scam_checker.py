"""
Scam Checker - Version 1.8
Checks a message, a link, or a saved web page for scam signs
in English, French, Spanish and Arabic.

1.5: text cleaning, links inside messages, fake-brand detection
1.6: online checks (domain age, certificate, Safe Browsing, redirects)
1.7: reads the page's source code (scripts, forms, fake links)
     and can inspect a saved page with --file
1.8: fake-shop checks (payment methods, missing About/Returns pages,
     too-good-to-be-true prices, fake urgency, card forms without https)

Usage:
  python scam_checker.py "message or link"
  python scam_checker.py --offline "message or link"      (no internet checks)
  python scam_checker.py --file page.html --host https://site.com (inspect a saved page)
"""

import argparse
import difflib
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup

from online_checks import (
    RISKY_ENDINGS,
    SHORTENERS,
    analyze_html,
    analyze_links,
    analyze_offers,
    analyze_payment,
    analyze_redirects,
    analyze_scripts,
    analyze_trust,
    check_certificate,
    fetch_page,
    get_host,
    lookup_domain_age,
    registered_domain,
    safe_browsing,
)


# ---------------------------------------------------------------
# STEP 1: Clean text so tricks and accents don't hide scam words.
# ---------------------------------------------------------------
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})


def _unleet(match):
    return match.group(0).translate(LEET)


def normalize(text):
    text = unicodedata.normalize("NFKD", text.lower())
    # remove accents (é -> e) and Arabic diacritics
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.replace("ـ", "")  # Arabic tatweel (stretching letter)
    text = text.replace("ى", "ي").replace("ة", "ه")
    text = text.replace("’", "'").replace("ʼ", "'")
    # words that mix letters and digits: "v3rify" -> "verify"
    text = re.sub(r"\b(?=\w*[a-z])(?=\w*\d)\w+\b", _unleet, text)
    # punctuation becomes spaces, then squeeze spaces
    text = re.sub(r"[^\w']+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------
# STEP 2: Load the scam phrase list from scam_phrases.csv (pandas).
# To add a phrase or a new language, just add a row to the CSV.
# ---------------------------------------------------------------
RULES = pd.read_csv(Path(__file__).with_name("scam_phrases.csv"), encoding="utf-8")
RULES["phrase"] = RULES["phrase"].apply(normalize)
RULES = RULES.drop_duplicates(subset="phrase")

BAIT_WORDS = ["login", "verify", "secure", "update", "account", "bonus", "prize",
              "free", "wallet", "claim", "outlet", "sale", "discount", "cheap",
              "clearance", "offer"]

# Brand name -> its real domains. A link that looks like the brand
# but is not on these domains is probably fake.
BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.dz", "google.com.ng", "googleapis.com",
               "googleusercontent.com", "gstatic.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "telegram": ["telegram.org", "t.me"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazonaws.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com"],
    "binance": ["binance.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "paystack": ["paystack.com"],
    "flutterwave": ["flutterwave.com"],
    "gtbank": ["gtbank.com"],
    "djezzy": ["djezzy.dz"],
    "mobilis": ["mobilis.dz"],
    "ooredoo": ["ooredoo.dz", "ooredoo.com"],
    "jumia": ["jumia.com"],
    "konga": ["konga.com"],
    "ouedkniss": ["ouedkniss.com"],
    "aliexpress": ["aliexpress.com"],
    "nike": ["nike.com"],
    "adidas": ["adidas.com"],
    "samsung": ["samsung.com"],
    "ikea": ["ikea.com"],
}

# Country endings used by the real regional sites of big companies
REGIONS = {"co.uk", "de", "fr", "es", "it", "dz", "ng", "com.ng", "com.dz", "co.za",
           "ca", "com.au", "in", "com.br", "eg", "com.eg", "ma", "tn", "co.ke"}

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


# ---------------------------------------------------------------
# STEP 3: Look for scam phrases using the pandas table.
# ---------------------------------------------------------------
def find_phrases(text):
    """The scam phrases found in the text, as a list of dictionaries."""
    clean = normalize(text)
    found = RULES[RULES["phrase"].apply(lambda p: p in clean)]
    return found.to_dict("records")


def check_text(text):
    found = find_phrases(text)
    reasons = [
        f'Found "{r["phrase"]}" ({r["language"]}, {r["category"]}, +{r["points"]})'
        for r in found
    ]
    return sum(int(r["points"]) for r in found), reasons


def fold(text):
    """Like normalize(), but never merges characters, so positions stay known."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.replace("ـ", "").replace("ى", "ي").replace("ة", "ه")
    return text.replace("’", "'").replace("ʼ", "'")


def highlight_segments(text, found):
    """Cut the message into pieces. Pieces that hold a scam phrase carry the
    phrase's details in "mark", the others have mark = None.
    (The website uses this to underline scam phrases in your own message.)"""
    folded, index = [], []
    for i, ch in enumerate(text):
        for f in fold(ch):
            folded.append(f)
            index.append(i)
    folded = "".join(folded)

    spans = []
    for item in found:
        pattern = r"\W+".join(re.escape(w) for w in item["phrase"].split())
        for m in re.finditer(pattern, folded):
            start, end = index[m.start()], index[m.end() - 1] + 1
            while end < len(text) and unicodedata.combining(text[end]):
                end += 1  # keep accents and Arabic marks with their letter
            spans.append((start, end, item))
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))

    segments, pos = [], 0
    for start, end, item in spans:
        if start < pos:
            continue  # overlaps one we already marked
        if start > pos:
            segments.append({"text": text[pos:start], "mark": None})
        segments.append({"text": text[start:end], "mark": item})
        pos = end
    if pos < len(text):
        segments.append({"text": text[pos:], "mark": None})
    return segments


# ---------------------------------------------------------------
# STEP 4: Check the link itself (no internet needed).
# ---------------------------------------------------------------
def is_official(host, official_domains):
    if any(host == d or host.endswith("." + d) for d in official_domains):
        return True
    # regional sites of the same company, e.g. amazon.co.uk or nike.dz
    name, _, region = registered_domain(host).partition(".")
    return region in REGIONS and any(d.split(".")[0] == name for d in official_domains)


def check_brand(host):
    """Return the brand name this host is pretending to be, or None."""
    tokens = normalize(host).split()
    for brand, official in BRANDS.items():
        if is_official(host, official):
            continue  # this is the real site
        for token in tokens:
            looks_like = (
                token == brand
                or (len(brand) >= 5 and (token.startswith(brand) or token.endswith(brand)))
                or (len(token) >= 5 and difflib.SequenceMatcher(None, token, brand).ratio() >= 0.82)
            )
            if looks_like:
                return brand
    return None


def check_page_brand(title, host):
    """Does the page title claim to be a brand that this site is not?"""
    tokens = normalize(title or "").split()
    for brand, official in BRANDS.items():
        if brand in tokens and not is_official(host, official):
            return 3, [f"Page title mentions {brand} but this is not an official {brand} site (+3)"]
    return 0, []


def check_link(url):
    reasons = []
    points = 0
    has_scheme = url.lower().startswith(("http://", "https://"))
    parsed = urlparse(url if has_scheme else "//" + url)
    host = (parsed.hostname or "").lower()

    if has_scheme and parsed.scheme == "http":
        reasons.append("Link does not use https (not secure) (+2)")
        points += 2
    if "@" in parsed.netloc:
        reasons.append("Link contains @, a trick to hide the real website (+4)")
        points += 4
    if re.fullmatch(r"[\d.]+", host) or ":" in host:
        reasons.append("Link uses a raw IP address instead of a name (+4)")
        points += 4
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        reasons.append("Link is shortened, so the real destination is hidden (+3)")
        points += 3
    if any(host.endswith(e) for e in RISKY_ENDINGS):
        reasons.append("Link ends with a domain often used in scams (+3)")
        points += 3
    if "xn--" in host:
        reasons.append("Link uses look-alike characters (punycode) (+3)")
        points += 3
    if host.count("-") >= 3:
        reasons.append("Link has many hyphens, common in fake sites (+2)")
        points += 2
    if host.count(".") >= 4:
        reasons.append("Link has too many sub-domains (+2)")
        points += 2

    brand = check_brand(host)
    if brand:
        reasons.append(f"Link imitates {brand} but is not an official {brand} site (+4)")
        points += 4

    bait = [w for w in BAIT_WORDS if w in host]
    if len(bait) >= 2:
        reasons.append(f"Link name stuffed with bait words ({', '.join(bait)}) (+3)")
        points += 3

    return points, reasons


# ---------------------------------------------------------------
# STEP 5: A Report collects every check and gives the verdict.
# ---------------------------------------------------------------
class Report:
    def __init__(self):
        self.score = 0
        self.reasons = []
        self.checks_run = []
        self.skipped = []

    def add(self, name, outcome, prefix=""):
        """outcome is (points, reasons), or None if the check could not run."""
        if outcome is None:
            self.skipped.append(name)
            return
        if name not in self.checks_run:
            self.checks_run.append(name)
        points, found = outcome
        self.score += points
        self.reasons.extend(prefix + r for r in found)

    def result(self):
        if self.score >= 8:
            verdict = "HIGH RISK"
        elif self.score >= 4:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LOW RISK"
        skipped = [s for s in dict.fromkeys(self.skipped) if s not in self.checks_run]
        return {
            "verdict": verdict,
            "score": self.score,
            "reasons": self.reasons,
            "checks_run": self.checks_run,
            "skipped": skipped,
        }


# ---------------------------------------------------------------
# STEP 6: Check a message or a link.
#
# online=True also does the online checks.
#   * Domain age and Safe Browsing only talk to third parties.
#   * Certificate, redirects and page checks contact the link's site,
#     so they only run when the input is ONE link (never for links
#     found inside a message).
# ---------------------------------------------------------------
def analyze(source, online=True):
    source = source.strip()
    report = Report()
    single_link = bool(URL_RE.fullmatch(source))
    page = None
    title = ""

    if single_link:
        links = [source]
        text = ""
        if online:
            try:
                page = fetch_page(source)
                soup = BeautifulSoup(page.text[:500_000], "html.parser")
                text = soup.get_text(separator=" ")
                title = soup.title.string if soup.title and soup.title.string else ""
            except requests.RequestException:
                report.skipped.append("page content")
    else:
        links = [u.rstrip(".,;:!?)") for u in URL_RE.findall(source)]
        text = source

    if text:
        report.add("scam phrases", check_text(text))

    for link in links:
        prefix = f"{link[:40]}: " if len(links) > 1 else ""
        report.add("link structure", check_link(link), prefix)

    if online:
        for link in links[:3]:
            prefix = f"{link[:40]}: " if len(links) > 1 else ""
            report.add("domain age", lookup_domain_age(get_host(link)), prefix)
            report.add("Google Safe Browsing", safe_browsing(link), prefix)

    if online and single_link:
        host = get_host(source)
        https_ok = not source.lower().startswith("http://")
        report.add("certificate", check_certificate(host) if https_ok else None)
        if page is not None:
            html = page.text[:500_000]
            chain = [r.url for r in page.history] + [page.url]
            final_host = get_host(page.url)
            report.add("redirects", analyze_redirects(chain))
            if registered_domain(final_host) != registered_domain(host):
                report.add("redirect destination", check_link(page.url), "After redirect: ")
            report.add("page forms", analyze_html(html, final_host))
            report.add("page scripts", analyze_scripts(html, final_host))
            report.add("page links", analyze_links(html, final_host))
            report.add("page title", check_page_brand(title, final_host))
            https = page.url.lower().startswith("https://")
            report.add("payment methods", analyze_payment(html, final_host, https))
            report.add("shop trust pages", analyze_trust(html, final_host))
            report.add("offers and style", analyze_offers(html, final_host))

    return report.result()


# ---------------------------------------------------------------
# STEP 7: Inspect a saved web page (no internet needed).
# In your browser: right-click the page > "Save as" > HTML only.
# ---------------------------------------------------------------
def analyze_saved_page(html, host="", https=None):
    host = host.lower().strip()
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string if soup.title and soup.title.string else ""

    report = Report()
    report.add("scam phrases", check_text(soup.get_text(separator=" ")))
    report.add("page forms", analyze_html(html, host))
    report.add("page scripts", analyze_scripts(html, host))
    report.add("page links", analyze_links(html, host))
    report.add("payment methods", analyze_payment(html, host, https))
    report.add("shop trust pages", analyze_trust(html, host))
    report.add("offers and style", analyze_offers(html, host))
    if host:
        report.add("page title", check_page_brand(title, host))
    return report.result()


# ---------------------------------------------------------------
# STEP 8: Run it.
# ---------------------------------------------------------------
def show(result):
    print(f"\nResult: {result['verdict']} (score {result['score']})")
    if result["reasons"]:
        print("Reasons:")
        for reason in result["reasons"]:
            print(f" - {reason}")
    else:
        print("No warning signs found. Still be careful.")
    print(f"\nChecks run: {', '.join(result['checks_run'])}")
    if result["skipped"]:
        print(f"Could not run: {', '.join(result['skipped'])}")
    print("\nA low score does not prove a site is safe. Polished sites can be fake too.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check a message or link for scam signs.")
    parser.add_argument("text", nargs="*", help="the message or link to check")
    parser.add_argument("--offline", action="store_true", help="skip all online checks")
    parser.add_argument("--file", help="a saved web page (.html) to inspect")
    parser.add_argument("--host", default="", help="site the saved page came from, e.g. example.com")
    args = parser.parse_args()

    if args.file:
        html = Path(args.file).read_text(encoding="utf-8", errors="ignore")
        host, https = args.host, None
        if "://" in host:  # a full address also tells us if https was used
            parsed = urlparse(host)
            host, https = parsed.hostname or "", parsed.scheme == "https"
        show(analyze_saved_page(html, host, https))
    else:
        user_input = " ".join(args.text) or input("Paste a link or message: ").strip()
        show(analyze(user_input, online=not args.offline))
