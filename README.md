# 🛡️ Scam Checker

An open-source, multilingual web application and analysis tool designed to detect scam messages, fraudulent links, and malicious web pages in **English, French, Spanish, and Arabic**. 

It analyzes text heuristics, keyword triggers, domain structural anomalies, and live page metadata (forms, scripts, redirects, and SSL status) to give users a clear risk score and breakdown.

---

## ✨ Key Features

* **Multilingual Rule Engine**: Parses and normalizes text (handling leetspeak, punctuation, and accents) to flag scam phrases.
* **Link & Domain Inspection**: Checks for risky top-level domains (TLDs like `.xyz`, `.top`), IP-address links, shortened URLs (`bit.ly`, etc.), and brand impersonation.
* **Deep Page Source Analysis**: When checking a website online or via saved HTML, it scans for:
  * Insecure or cross-site phishing login forms.
  * Hidden frames, obfuscated JavaScript, and crypto miners.
  * Missing e-commerce trust signals (About, Contact, Terms, and Return policies).
* **Interactive Markup**: Highlights exact scam phrases directly inside user-submitted messages.
* **API Support**: Includes a JSON API endpoint (`/api/check`) for programmatic integration.

---

## 🛠️ Tech Stack

* **Backend**: Python 3.10+, Flask
* **Data Parsing**: Pandas, BeautifulSoup4
* **Networking**: Requests
* **Frontend**: HTML5, Vanilla JavaScript, CSS3 (with responsive light/dark mode support)
* **Production Server**: Gunicorn

---

## 🚀 Getting Started Locally

### 1. Clone the Repository
```bash
git clone [https://github.com/YounesMlh/scam_checker.git](https://github.com/YounesMlh/scam_checker.git)
cd scam_checker
