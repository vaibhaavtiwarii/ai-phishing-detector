# Final version for cloud deployment
import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import os
import urllib.parse
import joblib
import pandas as pd
from scipy.sparse import hstack

from features import extract_features
from advisor import generate_security_advisory

# --- 1. CREDENTIALS (Supports Cloud Secrets or Local Fallback) ---
IMAP_SERVER = "imap.gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465

# Pulls securely from GitHub Actions secrets if running in the cloud, otherwise falls back to your local credentials
GMAIL_USER = os.getenv("GMAIL_USER", "vaibhavt.7895@gmail.com")
GMAIL_APP_PASS = os.getenv("GMAIL_APP_PASS", "giczzncpaqlkaluh")

# Enterprise Authority Allowlist & Trusted CDNs
TOP_VERIFIED_ROOTS = {
    # Core Tech & Identity Authorities
    "facebook.com", "fb.com", "google.com", "google.co.in", "youtube.com",
    "microsoft.com", "apple.com", "amazon.com", "amazon.in", "netflix.com",
    "github.com", "linkedin.com", "instagram.com", "twitter.com", "x.com",
    "wikipedia.org", "yahoo.com", "whatsapp.com", "zoom.us", "paypal.com",
    "spotify.com", "adobe.com", "dropbox.com", "stackoverflow.com", 
    "invertisuniversity.ac.in", "selfstudys.com", "codecademy.com",
    
    # Official Banking Authorities
    "sbi.co.in", "sbi.bank.in", "sbi.bank", "onlinesbi.sbi", "sbi",
    
    # Trusted Global CDNs & Hosted Resource Domains
    "gstatic.com", "googleapis.com", "googleusercontent.com", "google-analytics.com",
    "githubusercontent.com", "aws.amazon.com", "cloudfront.net", "akamaihd.net",
    "licdn.com", "media.licdn.com", "static.licdn.com", "github.githubassets.com",
    "w3.org", "cdn.bfldr.com", "library.iterable.com",

    # Verified ESP (Email Service Provider) Tracking Redirects
    "sparkpostmail.com", "sparkpostmail1.com", "sendgrid.net", "mailchimp.com",
    "links.codecademy.com"
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
pipeline = joblib.load("phishing_hybrid_pipeline.pkl")
model = pipeline['model']
vec_domain = pipeline['vec_domain']
vec_path = pipeline['vec_path']
lexical_columns = pipeline['lexical_columns']

def extract_urls(text):
    pattern = r'https?://[^\s<>"\',;]+'
    return list(set(re.findall(pattern, text)))

def audit_url(url_str):
    root_domain = get_root_domain(url_str)
    if root_domain in TOP_VERIFIED_ROOTS:
        return {"url": url_str, "is_phishing": False, "risk_score": 0.0, "tier": "Enterprise Allowlist", "threat_type": "Verified Safe Asset", "summary": f"Verified infrastructure parent domain '{root_domain}' is registered in our authority database.", "what_to_do": ["Proceed with normal browsing."], "what_not_to_do": ["No immediate security actions required."]}
    
    raw_lexical, domain_str, path_str = extract_features(url_str)
    dom_tf = vec_domain.transform([domain_str])
    path_tf = vec_path.transform([path_str])
    lex_df = pd.DataFrame([raw_lexical])[lexical_columns].fillna(0)
    
    fused = hstack([dom_tf, path_tf, lex_df.values]).tocsr()
    pred = int(model.predict(fused)[0])
    risk = float(model.predict_proba(fused)[0][1] * 100)
    is_phish = bool(pred == 1 or risk > 50)
    
    adv = generate_security_advisory(url_str, is_phish, risk, raw_lexical, domain_str, root_domain, False)
    
    return {
        "url": url_str,
        "is_phishing": is_phish,
        "risk_score": round(risk, 2),
        "tier": "LightGBM ML Classifier",
        "threat_type": adv["threat_type"],
        "summary": adv["summary"],
        "what_to_do": adv["what_to_do"],
        "what_not_to_do": adv["what_not_to_do"]
    }

def send_quarantine_alert(original_subject, sender, threats_found):
    try:
        msg = MIMEMultipart()
        msg["From"] = GMAIL_USER
        msg["To"] = GMAIL_USER
        msg["Subject"] = f"[🚨 AI PHISHING QUARANTINED] {original_subject}"

        body = f"""AI SECURITY GATEWAY INCIDENT REPORT
==================================
Original Sender: {sender}
Original Subject: {original_subject}
Status: 🛑 QUARANTINED (Moved to [Gmail]/Spam)

The AI Phishing Shield has intercepted and quarantined a malicious email.

DETECTED THREAT VECTORS:
-----------------------
"""
        for t in threats_found:
            body += f"\n• Malicious Link: {t['url']}\n  Risk Score: {t['risk_score']}%\n  Threat: {t['threat_type']}\n  Reason: {t.get('summary', '')}\n"

        body += "\nRECOMMENDED ACTIONS:\n"
        for item in threats_found[0].get("what_to_do", []):
            body += f"  🟢 {item}\n"
        for item in threats_found[0].get("what_not_to_do", []):
            body += f"  🔴 {item}\n"

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASS)
            server.send_message(msg)
        print(f"   📧 [INCIDENT ALERT] Warning email sent to {GMAIL_USER}")
    except Exception as e:
        print(f"   ❌ Failed to send alert email: {e}")

def scan_inbox(max_emails=10):
    print("=" * 65)
    print("🛡️ GMAIL AI SECURITY GATEWAY: SCANNING & AUTO-QUARANTINE")
    print("=" * 65)
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(GMAIL_USER, GMAIL_APP_PASS)
        mail.select("inbox")
    except Exception as e:
        print(f"❌ Authentication Failed: {e}")
        return

    status, messages = mail.search(None, 'UNSEEN')
    email_ids = messages[0].split()

    if not email_ids:
        print("📭 No unread emails in Inbox. System idle.")
        mail.close()
        mail.logout()
        return

    print(f"📬 Scanning {min(max_emails, len(email_ids))} unread messages...\n")

    for e_id in email_ids[-max_emails:]:
        res, msg_data = mail.fetch(e_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                subject_raw, encoding = decode_header(msg.get("Subject", "No Subject"))[0]
                subject = subject_raw.decode(encoding if encoding else "utf-8", errors="ignore") if isinstance(subject_raw, bytes) else subject_raw
                sender = msg.get("From", "Unknown Sender")

                print("-" * 65)
                print(f"📨 From: {sender}")
                print(f"📌 Subject: {subject}")

                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() in ["text/plain", "text/html"]:
                            try:
                                body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                            except: pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                    except: pass

                urls = extract_urls(body)
                if not urls:
                    print("   🟢 Verdict: No hyperlinks found in message body (Safe)")
                    continue

                print(f"   🔍 Embedded Links Found ({len(urls)}):")
                threats_found = [audit_url(u) for u in urls if audit_url(u)["is_phishing"]]

                if threats_found:
                    print(f"🚨 [PHISHING IDENTIFIED] Subject: '{subject}'")
                    print("   🛑 Initiating Auto-Quarantine and moving to [Gmail]/Spam...")
                    mail.copy(e_id, '[Gmail]/Spam')
                    mail.store(e_id, '+FLAGS', '\\Deleted')
                    mail.expunge()
                    send_quarantine_alert(subject, sender, threats_found)
                else:
                    print("\n   ✅ GATEWAY VERDICT: All verified links are clean.")
    mail.close()
    mail.logout()
    print("=" * 65)
    print("🛡️ Scan & Quarantine cycle complete.")

if __name__ == "__main__":
    scan_inbox(max_emails=10)