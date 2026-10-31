"""
Scam Checker website (Flask).

Run it locally:      python app.py     then open http://127.0.0.1:5000
Run in production:  gunicorn app:app
"""

import os
import re
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, render_template, request

from scam_checker import URL_RE, analyze, find_phrases, highlight_segments

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 20_000  # reject huge requests early

if os.environ.get("TRUST_PROXY"):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

MAX_CHARS = 3000
RATE_LIMIT, RATE_WINDOW = 15, 60  # max 15 checks per minute per visitor

EXAMPLES = [
    {
        "label": "Bank alert",
        "text": "URGENT: your account will be closed. Verify your account and enter your PIN "
                "at http://gtbank-update.top/login now.",
    },
    {
        "label": "Prix en français",
        "text": "Félicitations vous avez été sélectionné ! Réclamez votre prix et envoyez "
                "de l'argent pour les frais de livraison.",
    },
    {"label": "رسالة عربية", "text": "عاجل: لقد فزت! أدخل الرقم السري لحسابك لاستلام جائزتك"},
    {"label": "Message from a friend", "text": "Hi, are we still meeting at 5pm tomorrow?"},
]

VERDICTS = {
    "LOW RISK": {
        "key": "low",
        "title": "No strong warning signs",
        "advice": "That does not prove it is safe. If it asks for money, codes or passwords, "
                  "confirm with the sender in another way first.",
    },
    "SUSPICIOUS": {
        "key": "mid",
        "title": "Be careful with this one",
        "advice": "Do not click, pay or share codes yet. Contact the company through its "
                  "official app or website, not through this message.",
    },
    "HIGH RISK": {
        "key": "high",
        "title": "This looks like a scam",
        "advice": "Do not click links, reply, or send money, codes or passwords. Delete it. "
                  "If it uses a bank's or company's name, report it to them.",
    },
}

HITS = defaultdict(deque)
_lock = threading.Lock()


def rate_limited(visitor):
    now = time.time()
    with _lock:
        if len(HITS) > 10_000:
            HITS.clear()
        recent = HITS[visitor]
        while recent and now - recent[0] > RATE_WINDOW:
            recent.popleft()
        if len(recent) >= RATE_LIMIT:
            return True
        recent.append(now)
        return False


def split_points(reason):
    m = re.search(r"\s*\(\+(\d+)\)$", reason)
    if m:
        return reason[: m.start()], int(m.group(1))
    m = re.search(r", \+(\d+)\)$", reason)
    if m:
        return reason[: m.start()] + ")", int(m.group(1))
    return reason, None


def run_check(text, online):
    text = (text or "").strip()
    if not text:
        return None, "Paste a message or a link first.", 400
    if len(text) > MAX_CHARS:
        return None, f"That is too long. Paste up to {MAX_CHARS} characters.", 400
    if rate_limited(request.remote_addr or "unknown"):
        return None, "Too many checks in a short time. Wait a minute and try again.", 429

    try:
        result = analyze(text, online=online)
    except Exception:
        app.logger.exception("check failed")
        return None, "Something went wrong while checking. Try again, or turn off the online check.", 500

    result.update(VERDICTS[result["verdict"]])
    result["cells"] = min(result["score"], 12)
    result["is_link"] = bool(URL_RE.fullmatch(text))
    result["segments"] = [] if result["is_link"] else highlight_segments(text, find_phrases(text))
    result["reasons_view"] = [
        {"text": t, "points": p} for t, p in map(split_points, result["reasons"])
    ]
    return result, None, 200


def page(text="", online=True, result=None, error=None, status=200):
    html = render_template("index.html", text=text, online=online, result=result,
                           error=error, examples=EXAMPLES, max_chars=MAX_CHARS)
    return html, status


@app.get("/")
def index():
    return page()


@app.post("/")
def check_form():
    text = request.form.get("text", "")
    online = request.form.get("online") == "on"
    result, error, status = run_check(text, online)
    return page(text=text, online=online, result=result, error=error, status=status)


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    result, error, status = run_check(str(data.get("text", "")), bool(data.get("online", True)))
    if error:
        return jsonify(error=error), status
    return jsonify({k: result[k] for k in ("verdict", "score", "reasons", "checks_run", "skipped")})


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))