from flask import Flask, render_template, request, jsonify
import re
from urllib.parse import urlparse

app = Flask(__name__)


# =========================================================
# SUSPICIOUS TLDs
# =========================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".shop",
    ".work",
    ".online",
    ".site",
    ".live",
    ".vip",
    ".icu"
]


# =========================================================
# KNOWN URL SHORTENERS
# =========================================================

SHORTENED_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at"
]


# =========================================================
# TRUSTED COMPANY DOMAINS
# =========================================================

TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "ibm.com",
    "infosys.com",
    "tcs.com",
    "wipro.com",
    "accenture.com",
    "cognizant.com"
]


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    result = {
        "url": url,
        "score": 0,
        "risk": "LOW",
        "checks": [],
        "explanation": [],
        "recommendation": ""
    }

    try:

        parsed = urlparse(url)

        scheme = parsed.scheme.lower()

        hostname = parsed.hostname or ""

        hostname = hostname.lower()

        # -------------------------------------------------
        # HTTPS
        # -------------------------------------------------

        if scheme == "https":

            result["checks"].append({
                "status": "good",
                "message": "HTTPS connection detected"
            })

        elif scheme == "http":

            result["score"] += 15

            result["checks"].append({
                "status": "danger",
                "message": "HTTP connection detected instead of HTTPS"
            })

            result["explanation"].append(
                "The website does not use HTTPS encryption."
            )


        # -------------------------------------------------
        # IP ADDRESS
        # -------------------------------------------------

        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        if re.match(ip_pattern, hostname):

            result["score"] += 25

            result["checks"].append({
                "status": "danger",
                "message": "IP address used instead of a domain name"
            })

            result["explanation"].append(
                "The URL uses an IP address instead of a recognizable domain."
            )


        # -------------------------------------------------
        # SHORTENED URL
        # -------------------------------------------------

        if hostname in SHORTENED_DOMAINS:

            result["score"] += 25

            result["checks"].append({
                "status": "danger",
                "message": "Shortened URL detected"
            })

            result["explanation"].append(
                "The shortened URL hides the actual destination website."
            )


        # -------------------------------------------------
        # SUSPICIOUS TLD
        # -------------------------------------------------

        suspicious_tld_found = None

        for tld in SUSPICIOUS_TLDS:

            if hostname.endswith(tld):

                suspicious_tld_found = tld

                break


        if suspicious_tld_found:

            result["score"] += 15

            result["checks"].append({
                "status": "warning",
                "message": f"Potentially suspicious domain extension detected: {suspicious_tld_found}"
            })

            result["explanation"].append(
                "The domain uses an extension frequently seen in "
                "low-cost or disposable websites. This alone does not "
                "prove that the website is malicious."
            )


        # -------------------------------------------------
        # @ SYMBOL
        # -------------------------------------------------

        if "@" in url:

            result["score"] += 20

            result["checks"].append({
                "status": "danger",
                "message": "Suspicious @ symbol detected in URL"
            })

            result["explanation"].append(
                "The @ symbol can be abused to disguise the real destination."
            )


        # -------------------------------------------------
        # VERY LONG URL
        # -------------------------------------------------

        if len(url) > 100:

            result["score"] += 10

            result["checks"].append({
                "status": "warning",
                "message": "Unusually long URL detected"
            })

            result["explanation"].append(
                "Very long URLs can sometimes be used to hide suspicious parameters."
            )


        # -------------------------------------------------
        # MANY SUBDOMAINS
        # -------------------------------------------------

        domain_parts = hostname.split(".")

        if len(domain_parts) >= 5:

            result["score"] += 10

            result["checks"].append({
                "status": "warning",
                "message": "Multiple subdomains detected"
            })

            result["explanation"].append(
                "The domain contains an unusually large number of subdomains."
            )


        # -------------------------------------------------
        # SENSITIVE KEYWORDS
        # -------------------------------------------------

        suspicious_keywords = [
            "login",
            "verify",
            "account",
            "payment",
            "wallet",
            "secure",
            "update",
            "claim"
        ]

        found_keywords = []

        for word in suspicious_keywords:

            if word in hostname:

                found_keywords.append(word)


        if found_keywords:

            result["score"] += 10

            result["checks"].append({
                "status": "warning",
                "message": "Sensitive action keywords detected in domain"
            })

            result["explanation"].append(
                "The domain contains words such as "
                + ", ".join(found_keywords)
                + "."
            )


        # -------------------------------------------------
        # TRUSTED DOMAIN
        # -------------------------------------------------

        trusted = False

        for domain in TRUSTED_DOMAINS:

            if hostname == domain or hostname.endswith("." + domain):

                trusted = True

                break


        if trusted:

            result["score"] = max(0, result["score"] - 20)

            result["checks"].append({
                "status": "good",
                "message": "Recognized company domain detected"
            })

            result["explanation"].append(
                "The domain matches a recognized company domain in JobShield's reference list."
            )


        # -------------------------------------------------
        # LIMIT SCORE
        # -------------------------------------------------

        result["score"] = min(result["score"], 100)


        # -------------------------------------------------
        # RISK LEVEL
        # -------------------------------------------------

        if result["score"] >= 60:

            result["risk"] = "HIGH"

            result["recommendation"] = (
                "Avoid interacting with this URL until the destination "
                "has been independently verified."
            )

        elif result["score"] >= 20:

            result["risk"] = "MEDIUM"

            result["recommendation"] = (
                "Use caution. Verify the domain and company through "
                "official sources before sharing personal information."
            )

        else:

            result["risk"] = "LOW"

            result["recommendation"] = (
                "No major URL risk indicators were detected. "
                "Still verify the opportunity before sharing sensitive information."
            )


    except Exception:

        result["score"] = 50

        result["risk"] = "UNKNOWN"

        result["checks"].append({
            "status": "danger",
            "message": "Unable to safely analyze this URL"
        })

        result["recommendation"] = (
            "Do not trust this URL until it can be independently verified."
        )


    return result


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# MESSAGE ANALYSIS
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    message = data.get("message", "")

    text = message.lower()

    score = 0

    flags = []

    url_analysis = []


    # =====================================================
    # ADD FLAG
    # =====================================================

    def add_flag(title, description, severity, evidence):

        flags.append({
            "title": title,
            "description": description,
            "severity": severity,
            "evidence": evidence
        })


    # =====================================================
    # PAYMENT
    # =====================================================

    payment_patterns = [
        r"registration\s+fee",
        r"application\s+fee",
        r"processing\s+fee",
        r"joining\s+fee",
        r"security\s+deposit",
        r"refundable\s+(?:fee|deposit|amount)",
        r"pay\s+(?:₹|rs\.?|inr)?\s*\d+",
        r"payment\s+(?:of|for)",
        r"deposit\s+(?:of|₹|rs\.?|inr)",
        r"send\s+(?:₹|rs\.?|inr)?\s*\d+"
    ]

    payment_negations = [
        "no application fee",
        "no registration fee",
        "no processing fee",
        "no joining fee",
        "no security deposit",
        "no payment required",
        "no fee required",
        "without any fee",
        "free application",
        "free to apply"
    ]

    payment_detected = False
    payment_evidence = ""

    for pattern in payment_patterns:

        match = re.search(pattern, text)

        if match:

            payment_detected = True

            start = max(0, match.start() - 20)

            end = min(
                len(message),
                match.end() + 50
            )

            payment_evidence = message[start:end].strip()

            break


    payment_denied = any(
        phrase in text
        for phrase in payment_negations
    )


    if payment_detected and not payment_denied:

        score += 30

        add_flag(
            "Payment Request",
            "The message appears to request money, a fee, or a deposit from the applicant.",
            "high",
            payment_evidence
        )


    # =====================================================
    # SENSITIVE INFORMATION
    # =====================================================

    sensitive_patterns = [
        r"\baadhaar\b",
        r"\baadhar\b",
        r"\bpan\s+card\b",
        r"\bbank\s+details\b",
        r"\bbank\s+account\b",
        r"\baccount\s+number\b",
        r"\bcredit\s+card\b",
        r"\bdebit\s+card\b",
        r"\bupi\s+id\b",
        r"\botp\b",
        r"\bpassword\b",
        r"\batm\s+pin\b",
        r"\bpin\s+number\b"
    ]

    sensitive_detected = False
    sensitive_evidence = ""

    for pattern in sensitive_patterns:

        match = re.search(pattern, text)

        if match:

            sensitive_detected = True

            start = max(0, match.start() - 20)

            end = min(
                len(message),
                match.end() + 50
            )

            sensitive_evidence = message[start:end].strip()

            break


    if sensitive_detected:

        score += 25

        add_flag(
            "Sensitive Information Request",
            "The message requests potentially sensitive personal, financial, or authentication information.",
            "high",
            sensitive_evidence
        )


    # =====================================================
    # URGENCY
    # =====================================================

    urgency_patterns = [
        r"act\s+now",
        r"apply\s+now",
        r"immediately",
        r"urgent",
        r"today\s+only",
        r"only\s+today",
        r"last\s+chance",
        r"limited\s+seats?",
        r"limited\s+slots?",
        r"within\s+\d+\s+hours?",
        r"offer\s+expires?",
        r"do\s+not\s+delay"
    ]

    urgency_detected = False
    urgency_evidence = ""

    for pattern in urgency_patterns:

        match = re.search(pattern, text)

        if match:

            urgency_detected = True

            start = max(0, match.start() - 20)

            end = min(
                len(message),
                match.end() + 50
            )

            urgency_evidence = message[start:end].strip()

            break


    if urgency_detected:

        score += 10

        add_flag(
            "Urgency or Pressure",
            "The message uses pressure tactics that may encourage the recipient to act without verification.",
            "medium",
            urgency_evidence
        )


    # =====================================================
    # UNREALISTIC CLAIMS
    # =====================================================

    unrealistic_patterns = [
        r"guaranteed\s+(?:job|placement|income)",
        r"100%\s+(?:job|placement)",
        r"easy\s+money",
        r"earn\s+(?:₹|rs\.?|inr)?\s*\d+",
        r"make\s+(?:₹|rs\.?|inr)?\s*\d+\s+(?:per|a)\s+month",
        r"no\s+experience\s+(?:required|needed)",
        r"guaranteed\s+income"
    ]

    unrealistic_detected = False
    unrealistic_evidence = ""

    for pattern in unrealistic_patterns:

        match = re.search(pattern, text)

        if match:

            unrealistic_detected = True

            start = max(0, match.start() - 20)

            end = min(
                len(message),
                match.end() + 60
            )

            unrealistic_evidence = message[start:end].strip()

            break


    if unrealistic_detected:

        score += 15

        add_flag(
            "Unrealistic Employment Claim",
            "The message contains potentially unrealistic salary, income, or employment promises.",
            "medium",
            unrealistic_evidence
        )


    # =====================================================
    # SUSPICIOUS RECRUITMENT LANGUAGE
    # =====================================================

    scam_language_patterns = [
        r"selected\s+without\s+(?:interview|interviewing)",
        r"guaranteed\s+selection",
        r"instant\s+job",
        r"instant\s+joining",
        r"job\s+confirmed",
        r"no\s+interview",
        r"pay\s+to\s+get\s+(?:the\s+)?job",
        r"pay\s+to\s+secure\s+(?:the\s+)?(?:job|position)"
    ]

    scam_language_detected = False
    scam_language_evidence = ""

    for pattern in scam_language_patterns:

        match = re.search(pattern, text)

        if match:

            scam_language_detected = True

            start = max(0, match.start() - 20)

            end = min(
                len(message),
                match.end() + 60
            )

            scam_language_evidence = message[start:end].strip()

            break


    if scam_language_detected:

        score += 15

        add_flag(
            "Suspicious Recruitment Language",
            "The message contains recruitment claims commonly associated with potentially fraudulent offers.",
            "medium",
            scam_language_evidence
        )


    # =====================================================
    # URL DETECTION
    # =====================================================

    url_pattern = r"https?://[^\s]+|www\.[^\s]+"

    urls = re.findall(
        url_pattern,
        message
    )


    if urls:

        for url in urls:

            url = url.rstrip(
                ".,!?;:)"
            )


            if url.startswith("www."):

                analysis_url = "https://" + url

            else:

                analysis_url = url


            analysis = analyze_url(
                analysis_url
            )

            url_analysis.append(
                analysis
            )


        score += 10


        add_flag(
            "External Link Detected",
            "The message contains an external website link. JobShield also analyzed the URL for common risk indicators.",
            "medium",
            urls[0]
        )


        highest_url_score = max(
            item["score"]
            for item in url_analysis
        )


        if highest_url_score >= 60:

            score += 25

        elif highest_url_score >= 20:

            score += 15


    # =====================================================
    # UNOFFICIAL CHANNEL
    # =====================================================

    unofficial_patterns = [
        r"contact\s+me\s+on\s+whatsapp",
        r"message\s+me\s+on\s+whatsapp",
        r"contact\s+via\s+telegram",
        r"message\s+me\s+on\s+telegram",
        r"whatsapp\s+only",
        r"telegram\s+only"
    ]

    unofficial_detected = False
    unofficial_evidence = ""

    for pattern in unofficial_patterns:

        match = re.search(pattern, text)

        if match:

            unofficial_detected = True

            start = max(
                0,
                match.start() - 20
            )

            end = min(
                len(message),
                match.end() + 50
            )

            unofficial_evidence = message[start:end].strip()

            break


    if unofficial_detected:

        score += 10

        add_flag(
            "Unofficial Communication Channel",
            "The recruiter appears to rely on a messaging platform instead of a clearly identifiable official recruitment channel.",
            "medium",
            unofficial_evidence
        )


    # =====================================================
    # MULTIPLE RED FLAGS
    # =====================================================

    red_flag_count = sum([
        payment_detected and not payment_denied,
        sensitive_detected,
        urgency_detected,
        unrealistic_detected,
        scam_language_detected
    ])


    if red_flag_count >= 3:

        score += 10

        add_flag(
            "Multiple Scam Indicators",
            "Several independent warning signs appear together, increasing the overall risk.",
            "high",
            "Multiple independent indicators detected"
        )


    # =====================================================
    # SCORE LIMIT
    # =====================================================

    score = min(
        score,
        100
    )


    # =====================================================
    # RISK LEVEL
    # =====================================================

    if score >= 76:

        risk = "🔴 CRITICAL RISK"

        recommendation = (
            "Do not make payments or share sensitive information. "
            "Verify the employer independently through its official website "
            "and official contact channels."
        )

    elif score >= 51:

        risk = "🟠 HIGH RISK"

        recommendation = (
            "Proceed with extreme caution. Do not send money or sensitive "
            "information until the employer and recruitment process have "
            "been independently verified."
        )

    elif score >= 21:

        risk = "🟡 SUSPICIOUS"

        recommendation = (
            "Some warning signs were detected. Verify the company, recruiter, "
            "website, and recruitment process using independent official sources."
        )

    else:

        risk = "🟢 LOW RISK"

        recommendation = (
            "No major scam indicators were detected in the provided message. "
            "This does not guarantee that the opportunity is legitimate."
        )


    # =====================================================
    # NO FLAGS
    # =====================================================

    if not flags:

        flags.append({
            "title": "No Major Red Flags",
            "description": "No major scam indicators were detected.",
            "severity": "low",
            "evidence": ""
        })


    # =====================================================
    # RESPONSE
    # =====================================================

    return jsonify({

        "score": score,

        "risk": risk,

        "flags": flags,

        "recommendation": recommendation,

        "url_analysis": url_analysis

    })


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )