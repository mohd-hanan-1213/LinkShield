import re
from urllib.parse import urlparse, unquote
import json
import sys

def normalize_domain(domain):
    replacements = {
        '0': 'o',
        '1': 'l',
        '2': 'z',
        '3': 'e',
        '5': 's',
        '6': 'g',
        '7': 't',
        '9': 'g',
        '@': 'a',
        '$': 's',
        '!': 'i'
    }
    return ''.join(replacements.get(c, c) for c in domain)



def analyze_url(url):
    score = 0
    reasons = []

    url_lower = url.lower()

    #  Unsafe URL schemes
    scheme = url.split(":")[0].lower()

    if scheme in ["javascript", "data"]:
        return {
            "risk": "HIGH",
            "score": 100,
            "reasons": [f"Uses unsafe URL scheme ({scheme})"]
        }

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    decoded_url = unquote(url)

    has_ip = False
    has_at = False
    has_shortener = False
    no_https = False
    suspicious_domain = False

    #  '@' symbol
    if '@' in url:
        has_at = True
        reasons.append("Contains '@' symbol")

    # IP address
    ip_pattern = r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        has_ip = True
        reasons.append("Uses IP address instead of domain")

    # Shorteners
    shorteners = [
        "bit.ly","tinyurl.com","goo.gl","t.co","ow.ly","is.gd",
        "buff.ly","adf.ly","cutt.ly","rebrand.ly","shorte.st",
        "soo.gd","s2r.co","tiny.cc","clicky.me","bl.ink",
        "rb.gy","clck.ru","v.gd","lnkd.in","db.tt"
    ]
    if any(s in domain for s in shorteners):
        has_shortener = True
        reasons.append("Uses URL shortener")

    # HTTPS
    if url.startswith("http://"):
        no_https = True
        reasons.append("Does not use HTTPS")

    # Dot count
    dot_count = url.count('.')
    if dot_count > 4:
        score += 15
        reasons.append("Too many subdomains")

    # URL length
    if len(url) > 75:
        score += 20
        reasons.append("URL is too long")

    # DOMAIN IMPERSONATION

    brands = ["paypal", "google", "facebook", "amazon", "instagram", "bank"]
    keywords = ["login", "secure", "verify", "update", "account"]

    normalized = normalize_domain(domain)

    # Lookalike detection
    for b in brands:
        if b in normalized and b not in domain:
            suspicious_domain = True
            reasons.append("Lookalike domain (character substitution)")

    # Brand + keyword
    if any(b in domain for b in brands) and any(k in domain for k in keywords):
        suspicious_domain = True
        reasons.append("Brand name with suspicious keywords")

    # Brand in subdomain
    parts = domain.split('.')
    if len(parts) >= 2:
        main_domain = ".".join(parts[-2:])
        if any(b in domain and b not in main_domain for b in brands):
            suspicious_domain = True
            reasons.append("Brand in subdomain (possible spoofing)")

    if suspicious_domain:
        score += 30

        # Boost clean-looking impersonation
        if not has_ip and not has_at and not has_shortener:
            score += 20
            reasons.append("Clean-looking impersonation domain")

    # OPEN REDIRECT
    redirect_params = ["url=", "redirect=", "next=", "target=", "dest="]

    if any(p in decoded_url.lower() for p in redirect_params) and ("http://" in decoded_url or "https://" in decoded_url):
        score += 25
        reasons.append("Possible open redirect (embedded URL)")

    # CRITICAL RULES
    if (has_ip and has_at) or \
       (has_at and has_shortener) or \
       (has_ip and no_https) or \
       (no_https and dot_count > 4) or \
       (suspicious_domain and (has_at or has_ip)) or \
       (suspicious_domain and no_https):
        return {
            "risk": "HIGH",
            "score": 100,
            "reasons": reasons + ["Critical phishing pattern detected"]
        }


    #SCORING
    if has_ip:
        score += 30
    if has_at:
        score += 25
    if has_shortener:
        score += 25
    if no_https:
        score += 15


    #FINAL CLASSIFICATION
    if score >= 60:
        risk = "HIGH"
    elif score >= 25:
        risk = "SUSPICIOUS"
    else:
        risk = "SAFE"

    return {
        "risk": risk,
        "score": score,
        "reasons": reasons
    }

# TEST
if __name__ == "__main__":
    # Get URL from command line (sent by server.js)
    url = sys.argv[1]

    result = analyze_url(url)

    # Output JSON (Node.js will read this)
    print(json.dumps(result))
