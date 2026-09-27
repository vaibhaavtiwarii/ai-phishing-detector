def generate_security_advisory(url_str, is_phishing, risk_score, heuristics, domain_str, root_domain, is_allowlisted=False):
    """
    Generates dynamic, context-specific security guidance based on real-time threat indicators.
    """
    # 1. Verified Safe / Global Authority
    if is_allowlisted or risk_score < 15:
        return {
            "threat_type": "Verified Safe Asset",
            "summary": f"'{root_domain}' is a recognized, trusted authority domain with authentic structural integrity.",
            "what_to_do": [
                "Proceed with normal browsing and secure sign-in.",
                "Ensure your connection displays the standard padlock icon in the browser address bar."
            ],
            "what_not_to_do": [
                "No immediate restrictions. Still adhere to standard cyber hygiene."
            ]
        }

    # 2. Low-to-Moderate Suspicion (Gray Zone: 15% - 50%)
    if not is_phishing and risk_score <= 50:
        return {
            "threat_type": "Unverified or Low-Reputation Domain",
            "summary": f"This domain is not recognized on authority registries. While not an overt attack, caution is advised.",
            "what_to_do": [
                "Verify the organization identity before sharing email addresses or phone numbers.",
                "Bookmark official portals directly instead of relying on links sent via SMS or chat."
            ],
            "what_not_to_do": [
                "Do NOT enter sensitive credentials unless you have independently verified ownership.",
                "Avoid downloading executable (.exe, .bat, .zip) files from this site."
            ]
        }

    # 3. High Risk Threats (>50% Risk): Tailor specifically to the detected vector
    threat_reasons = []
    what_to_do = []
    what_not_to_do = [
        "Do NOT enter usernames, passwords, credit card numbers, or two-factor authentication (OTP) codes.",
        "Do NOT authorize permissions or download any profile/extensions requested by this page."
    ]

    # Specific Heuristic 1: Brand Spoofing (e.g. Canva/PayPal impersonation)
    if heuristics.get("has_brand_spoofing"):
        threat_reasons.append(f"Impersonation attack detected: Brand keywords are housed inside unauthorized infrastructure ({domain_str}).")
        what_to_do.append("Open a new browser tab and navigate to the brand's verified official website directly.")
        what_not_to_do.append("Do NOT trust visual brand logos displayed on this page—they are copied assets.")

    # Specific Heuristic 2: Suspicious Cheap TLD
    if heuristics.get("is_suspicious_tld"):
        threat_reasons.append(f"Uses an anomalous high-risk Top-Level Domain commonly used for short-lived phishing campaigns.")
        what_to_do.append("Inspect the exact spelling of the domain preceding the extension.")

    # Specific Heuristic 3: High Entropy / Randomness
    if heuristics.get("entropy", 0) > 3.4:
        threat_reasons.append("Contains machine-generated random character strings indicative of evasive phishing tunnels.")
        what_to_do.append("Report this link to your organization's IT security team or email provider.")

    # Specific Heuristic 4: Unsecured HTTP
    if "https://" not in url_str.lower():
        threat_reasons.append("Unencrypted connection (HTTP): Any submitted data can be intercepted by third parties.")
        what_not_to_do.append("Do NOT submit payment or authentication data across an unencrypted connection.")

    # Fallback if no specific heuristic fired but ML model detected threat
    if not threat_reasons:
        threat_reasons.append("Structural and character n-gram analysis matches confirmed credential-harvesting patterns.")
        what_to_do.append("Close this browser tab immediately.")

    what_to_do.append("If you have already entered credentials here, immediately reset your real account password elsewhere.")

    return {
        "threat_type": "Credential-Harvesting Phishing Attack",
        "summary": " ".join(threat_reasons),
        "what_to_do": what_to_do,
        "what_not_to_do": what_not_to_do
    }
