import imaplib
import email
from email.header import decode_header
import re
import urllib.parse
import joblib
import pandas as pd
from scipy.sparse import hstack

from features import extract_features
from advisor import generate_security_advisory

# --- 1. CONFIGURATION ---
IMAP_SERVER = "imap.gmail.com"
GMAIL_USER = "vaibhavt.7895@gmail.com"          # <-- Replace with your Gmail address
GMAIL_APP_PASS = "giczzncpaqlkaluh" # <-- Replace with your 16-character App Password

# Enterprise Authority Allowlist & Trusted CDNs
TOP_VERIFIED_ROOTS = {
    # Core Tech & Identity Authorities
    "facebook.com", "fb.com", "google.com", "google.co.in", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "amazon.in", "netflix.com",
    "github.com", "linkedin.com", "instagram.com", "twitter.com", "x.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "zoom.us", "paypal.com",
    "spotify.com", "adobe.com", "dropbox.com", "stackoverflow.com", 
    "invertisuniversity.ac.in", "selfstudys.com",
    
    # Official Banking Authorities (State Bank of India)
    "sbi.co.in", "sbi.bank.in", "sbi.bank", "onlinesbi.sbi", "sbi",
    
    # Trusted Global CDNs & Hosted Resource Domains (Added LinkedIn & Codecademy CDNs)
    "gstatic.com", "googleapis.com", "googleusercontent.com", "google-analytics.com",
    "githubusercontent.com", "aws.amazon.com", "cloudfront.net", "akamaihd.net",
    "licdn.com", "media.licdn.com", "static.licdn.com", "github.githubassets.com",
    "w3.org", "cdn.bfldr.com", "library.iterable.com",
    
    # Verified ESP (Email Service Provider) Tracking Redirects
    "sparkpostmail.com", "sparkpostmail1.com", "sendgrid.net", "mailchimp.com",
    "codecademy.com", "links.codecademy.com"
}



def get_root_domain(url_str):
    try:
        parsed = urllib.parse.urlparse(url_str if '://' in url_str else 'http://' + url_str)
        domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower().split('/')[0]
        parts = domain.split('.')
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain
    except Exception:
        return ""

# --- 2. LOAD PIPELINE ARTIFACTS ---
print("📦 Loading 96.27% Dual-Engine LightGBM Pipeline...")
pipeline = joblib.load("phishing_hybrid_pipeline.pkl")
model = pipeline['model']
vec_domain = pipeline['vec_domain']
vec_path = pipeline['vec_path']
lexical_columns = pipeline['lexical_columns']
print("✅ Threat engine ready.\n")

def extract_urls(text):
    """Extracts all HTTP/HTTPS links from email body text and HTML."""
    pattern = r'https?://[^\s<>"\',;]+'
    return list(set(re.findall(pattern, text)))

def audit_url(url_str):
    """Evaluates a single URL against Allowlist + LightGBM."""
    root_domain = get_root_domain(url_str)
    
    # Tier 1: Allowlist Check
    if root_domain in TOP_VERIFIED_ROOTS:
        return {
            "url": url_str,
            "is_phishing": False,
            "risk_score": 0.0,
            "tier": "Enterprise Allowlist",
            "threat_type": "Verified Safe Asset"
        }
    
    # Tier 2: Machine Learning Inference
    raw_lexical, domain_str, path_str = extract_features(url_str)
    dom_tf = vec_domain.transform([domain_str])
    path_tf = vec_path.transform([path_str])
    lex_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)
    
    fused = hstack([dom_tf, path_tf, lex_df.values]).tocsr()
    pred = int(model.predict(fused)[0])
    risk = float(model.predict_proba(fused)[0][1] * 100)
    is_phish = bool(pred == 1 or risk > 50)
    
    adv = generate_security_advisory(
        url_str=url_str,
        is_phishing=is_phish,
        risk_score=risk,
        heuristics=raw_lexical,
        domain_str=domain_str,
        root_domain=root_domain,
        is_allowlisted=False
    )
    
    return {
        "url": url_str,
        "is_phishing": is_phish,
        "risk_score": round(risk, 2),
        "tier": "LightGBM ML Classifier",
        "threat_type": adv["threat_type"],
        "summary": adv["summary"],
        "what_not_to_do": adv["what_not_to_do"]
    }

def scan_inbox(max_emails=5):
    """Connects to Gmail, scans unread messages, and audits embedded links."""
    print("=" * 65)
    print("🛡️ GMAIL AI SECURITY GATEWAY: SCANNING UNREAD MESSAGES")
    print("=" * 65)

    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(GMAIL_USER, GMAIL_APP_PASS)
        mail.select("inbox")
    except Exception as e:
        print(f"❌ Authentication Failed: {e}")
        print("💡 Ensure you are using your 16-character App Password, not your regular password.")
        return

    # Search for UNSEEN (unread) emails
    status, messages = mail.search(None, 'UNSEEN')
    email_ids = messages[0].split()

    if not email_ids:
        print("📭 No unread emails found in Inbox. You're all caught up!")
        mail.close()
        mail.logout()
        return

    print(f"📬 Found {len(email_ids)} unread email(s). Auditing the latest {min(max_emails, len(email_ids))}...\n")

    for e_id in email_ids[-max_emails:]:
        res, msg_data = mail.fetch(e_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                # Decode Subject
                subject_raw, encoding = decode_header(msg.get("Subject", "No Subject"))[0]
                if isinstance(subject_raw, bytes):
                    subject = subject_raw.decode(encoding if encoding else "utf-8", errors="ignore")
                else:
                    subject = subject_raw
                
                sender = msg.get("From", "Unknown Sender")

                print("-" * 65)
                print(f"📨 From: {sender}")
                print(f"📌 Subject: {subject}")

                # Extract message body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type in ["text/plain", "text/html"]:
                            try:
                                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                            except Exception:
                                pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                    except Exception:
                        pass

                # Scan for links
                urls = extract_urls(body)
                if not urls:
                    print("   🟢 Verdict: No hyperlinks found in message body (Safe)")
                    continue

                print(f"   🔍 Embedded Links Found ({len(urls)}):")
                email_has_threat = False

                for u in urls:
                    result = audit_url(u)
                    if result["is_phishing"]:
                        email_has_threat = True
                        print(f"   🚨 [THREAT DETECTED] {u}")
                        print(f"      • Threat Class: {result['threat_type']}")
                        print(f"      • Risk Score  : {result['risk_score']}% ({result['tier']})")
                        print(f"      • Reason      : {result.get('summary', 'Deceptive pattern match')}")
                        print(f"      • Caution     : {result.get('what_not_to_do', ['Do not click'])[0]}")
                    else:
                        print(f"   ✅ [SAFE LINK] {u} (Risk: {result['risk_score']}%)")

                if email_has_threat:
                    print("\n   ⚠️ GATEWAY VERDICT: PHISHING ATTACK IDENTIFIED IN THIS EMAIL.")
                    print("      RECOMMENDATION: Quarantine email, do not click links or input credentials.")
                else:
                    print("\n   ✅ GATEWAY VERDICT: All verified links are clean.")

    mail.close()
    mail.logout()
    print("=" * 65)
    print("🛡️ Scan cycle complete.")

if __name__ == "__main__":
    scan_inbox(max_emails=5)
