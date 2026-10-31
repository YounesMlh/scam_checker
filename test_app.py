"""
Tests for the website. Run with:  python test_app.py
They never use the internet (the form's "online" box is left unticked).
"""

import app as site

client = site.app.test_client()


def post(text, **extra):
    site.HITS.clear()
    return client.post("/", data={"text": text, **extra})


def body(response):
    return response.get_data(as_text=True)


def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Is this message a scam?" in body(response)


def test_scam_message_shows_verdict_and_marks():
    response = post("URGENT: verify your account and enter your PIN")
    html = body(response)
    assert response.status_code == 200
    assert "High risk" in html
    assert "<mark" in html
    assert "Why" in html


def test_safe_message_has_no_marks():
    html = body(post("Hi, are we still meeting at 5pm tomorrow?"))
    assert "Low risk" in html
    assert "<mark" not in html


def test_link_is_checked_without_marked_message():
    html = body(post("https://bit.ly/abc"))
    assert "Your message, marked up" not in html
    assert "shortened" in html


def test_empty_input():
    response = post("   ")
    assert response.status_code == 400
    assert "Paste a message" in body(response)


def test_too_long_input():
    response = post("a" * 3001)
    assert response.status_code == 400
    assert "too long" in body(response)


def test_html_in_message_is_escaped():
    html = body(post("<script>alert(1)</script> urgent"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_api():
    site.HITS.clear()
    response = client.post("/api/check", json={"text": "URGENT verify your account", "online": False})
    data = response.get_json()
    assert response.status_code == 200
    assert data["verdict"] == "SUSPICIOUS" or data["verdict"] == "HIGH RISK"
    assert set(data) == {"verdict", "score", "reasons", "checks_run", "skipped"}


def test_api_errors():
    site.HITS.clear()
    response = client.post("/api/check", json={"text": ""})
    assert response.status_code == 400 and "error" in response.get_json()


def test_rate_limit():
    site.HITS.clear()
    for _ in range(site.RATE_LIMIT):
        assert client.post("/", data={"text": "hello"}).status_code == 200
    response = client.post("/", data={"text": "hello"})
    assert response.status_code == 429
    assert "Too many checks" in body(response)
    site.HITS.clear()


def test_security_headers():
    headers = client.get("/").headers
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_split_points():
    assert site.split_points("Link is shortened (+3)") == ("Link is shortened", 3)
    assert site.split_points('Found "urgent" (English, urgency, +2)') == (
        'Found "urgent" (English, urgency)', 2)
    assert site.split_points("No number here") == ("No number here", None)


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
